<?php

namespace Glitter\SocialTOTPPasskey\Passkey;

use App\Models\User;
use App\Services\PluginSettingsService;
use Glitter\SocialTotpPasskey\Vendor\Cose\Algorithm\Signature\ECDSA\ES256;
use Glitter\SocialTotpPasskey\Vendor\Cose\Algorithm\Signature\RSA\RS256;
use Glitter\SocialTOTPPasskey\Auth\ReauthenticationRequiredException;
use Glitter\SocialTOTPPasskey\Auth\SocialTotpService;
use Glitter\SocialTOTPPasskey\Models\PasskeyCredential;
use Glitter\SocialTOTPPasskey\Models\SocialAccount;
use Glitter\SocialTOTPPasskey\Models\SocialLoginTotp;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Glitter\SocialTotpPasskey\Vendor\Symfony\Component\Serializer\SerializerInterface;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\AuthenticatorAssertionResponse;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\AuthenticatorAssertionResponseValidator;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\AuthenticatorAttestationResponse;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\AuthenticatorAttestationResponseValidator;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\AuthenticatorSelectionCriteria;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\CredentialRecord;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\Denormalizer\WebauthnSerializerFactory;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\PublicKeyCredential;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\PublicKeyCredentialCreationOptions;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\PublicKeyCredentialParameters;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\PublicKeyCredentialRequestOptions;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\PublicKeyCredentialRpEntity;
use Glitter\SocialTotpPasskey\Vendor\Webauthn\PublicKeyCredentialUserEntity;

final class PasskeyService
{
    public const IDENTIFIER = 'glitter-social_totp_passkey';

    public const ERROR_REAUTHENTICATION_CREDENTIAL_MISSING = 'passkey_reauthentication_credential_missing';

    private const CHALLENGE_TTL_SECONDS = 300;

    private const AUTHENTICATION_EVIDENCE_TTL_SECONDS = 120;

    private const CACHE_PREFIX = 'glitter_social_totp_passkey:passkey:';

    private ?SerializerInterface $serializer = null;

    public function __construct(
        private readonly PluginSettingsService $settings,
        private readonly SocialTotpService $totp,
    ) {}

    public function enabled(): bool
    {
        return (bool) $this->settings->get(self::IDENTIFIER, 'passkey_enabled', false);
    }

    public function loginEnabled(): bool
    {
        return $this->enabled()
            && (bool) $this->settings->get(self::IDENTIFIER, 'passkey_login_enabled', true);
    }

    public function substitutionEnabled(): bool
    {
        return $this->enabled()
            && (bool) $this->settings->get(self::IDENTIFIER, 'passkey_totp_substitution_enabled', false);
    }

    public function loginRequiresTotp(): bool
    {
        return (bool) $this->settings->get(self::IDENTIFIER, 'passkey_login_requires_totp', false);
    }

    /** @return array<string, mixed> */
    public function beginRegistration(User $user, string $reauthToken, string $sessionId, string $userAgent): array
    {
        if (! $this->enabled()
            || ! (bool) $this->settings->get(self::IDENTIFIER, 'passkey_registration_enabled', true)
        ) {
            throw new \RuntimeException('passkey_registration_disabled');
        }

        $this->totp->assertReauthentication($user, $reauthToken, $sessionId, $userAgent);
        [$rpId, $origin] = $this->relyingParty();
        $handle = $this->userHandleFor($user);
        $userEntity = PublicKeyCredentialUserEntity::create(
            (string) ($user->email ?: $user->getKey()),
            $this->base64UrlDecode($handle),
            (string) ($user->name ?: $user->nickname ?: $user->email ?: $user->getKey()),
        );
        $credentials = $this->credentialsForUser($user);
        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create((string) config('app.name', $rpId), $rpId),
            $userEntity,
            random_bytes(32),
            [PublicKeyCredentialParameters::createPk(ES256::ID), PublicKeyCredentialParameters::createPk(RS256::ID)],
            AuthenticatorSelectionCriteria::create(
                userVerification: $this->userVerification(),
                residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            array_map(static fn (CredentialRecord $record) => $record->getPublicKeyCredentialDescriptor(), $credentials),
            60000,
        );

        return $this->storeChallenge('register', $options, $sessionId, $userAgent, [
            'user_id' => (int) $user->getKey(),
            'reauth_hash' => hash('sha256', $reauthToken),
            'origin' => $origin,
        ]);
    }

    public function finishRegistration(
        User $user,
        string $challengeId,
        array $credentialPayload,
        string $name,
        string $reauthToken,
        string $sessionId,
        string $userAgent,
    ): PasskeyCredential {
        $this->assertAvailable();
        $this->totp->assertReauthentication($user, $reauthToken, $sessionId, $userAgent);
        $challenge = $this->consumeChallenge($challengeId, 'register', $sessionId, $userAgent);

        if ((int) ($challenge['user_id'] ?? 0) !== (int) $user->getKey()
            || ! hash_equals((string) ($challenge['reauth_hash'] ?? ''), hash('sha256', $reauthToken))
        ) {
            throw new \RuntimeException('passkey_challenge_invalid');
        }

        $options = $this->deserialize((string) $challenge['options'], PublicKeyCredentialCreationOptions::class);
        $credential = $this->loadCredential($credentialPayload);
        if (! $credential->response instanceof AuthenticatorAttestationResponse) {
            throw new \RuntimeException('passkey_attestation_invalid');
        }

        [$rpId, $origin] = $this->relyingParty();
        if (! hash_equals((string) ($challenge['origin'] ?? ''), $origin)) {
            throw new \RuntimeException('passkey_origin_changed');
        }
        $record = AuthenticatorAttestationResponseValidator::create($this->ceremonyFactory($origin)->creationCeremony())
            ->check($credential->response, $options, $rpId);
        $credentialId = $this->base64UrlEncode($record->publicKeyCredentialId);
        $hash = hash('sha256', $record->publicKeyCredentialId);

        return DB::transaction(function () use ($user, $record, $credentialId, $hash, $name): PasskeyCredential {
            if (PasskeyCredential::query()->where('credential_id_hash', $hash)->lockForUpdate()->exists()) {
                throw new \RuntimeException('passkey_credential_duplicate');
            }

            return PasskeyCredential::query()->create([
                'user_id' => (int) $user->getKey(),
                'credential_id_hash' => $hash,
                'credential_id' => $credentialId,
                'user_handle' => $this->base64UrlEncode($record->userHandle),
                'credential_record' => $this->serializer()->serialize($record, 'json'),
                'public_key' => $this->base64UrlEncode($record->credentialPublicKey),
                'signature_counter' => $record->counter,
                'transports' => $record->transports,
                'aaguid' => $record->aaguid->toRfc4122(),
                'name' => Str::limit(trim($name) ?: 'Passkey', 100, ''),
                'backup_eligible' => $record->backupEligible,
                'backup_status' => $record->backupStatus,
            ]);
        });
    }

    /** @return array<string, mixed> */
    public function beginAuthentication(
        string $purpose,
        string $sessionId,
        string $userAgent,
        ?User $expectedUser = null,
        ?string $context = null,
    ): array {
        $this->assertPurposeEnabled($purpose);
        $records = $expectedUser ? $this->credentialsForUser($expectedUser) : [];

        if ($purpose === 'reauth' && $records === []) {
            throw new \RuntimeException(self::ERROR_REAUTHENTICATION_CREDENTIAL_MISSING);
        }

        [$rpId, $origin] = $this->relyingParty();
        $options = PublicKeyCredentialRequestOptions::create(
            random_bytes(32),
            $rpId,
            array_map(static fn (CredentialRecord $record) => $record->getPublicKeyCredentialDescriptor(), $records),
            in_array($purpose, ['login', 'social', 'reauth'], true) ? 'required' : $this->userVerification(),
            60000,
        );

        return $this->storeChallenge($purpose, $options, $sessionId, $userAgent, [
            'user_id' => $expectedUser?->getKey(),
            'context_hash' => $context === null ? null : hash('sha256', $context),
            'origin' => $origin,
        ]);
    }

    public function finishAuthentication(
        string $purpose,
        string $challengeId,
        array $credentialPayload,
        string $sessionId,
        string $userAgent,
        ?string $context = null,
    ): PasskeyAuthenticationResult {
        $this->assertPurposeEnabled($purpose);
        $challenge = $this->consumeChallenge($challengeId, $purpose, $sessionId, $userAgent);
        $expectedContextHash = $challenge['context_hash'] ?? null;
        if (($expectedContextHash !== null || $context !== null)
            && (! is_string($expectedContextHash) || $context === null
                || ! hash_equals($expectedContextHash, hash('sha256', $context)))) {
            throw new \RuntimeException('passkey_context_invalid');
        }

        $credential = $this->loadCredential($credentialPayload);
        if (! $credential->response instanceof AuthenticatorAssertionResponse) {
            throw new \RuntimeException('passkey_assertion_invalid');
        }
        $credentialHash = hash('sha256', $credential->rawId);
        [$rpId, $origin] = $this->relyingParty();
        if (! hash_equals((string) ($challenge['origin'] ?? ''), $origin)) {
            throw new \RuntimeException('passkey_origin_changed');
        }

        return DB::transaction(function () use ($challenge, $credential, $credentialHash, $purpose, $rpId, $origin): PasskeyAuthenticationResult {
            $stored = PasskeyCredential::query()->where('credential_id_hash', $credentialHash)->lockForUpdate()->first();
            if (! $stored || ((int) ($challenge['user_id'] ?? 0) !== 0
                    && (int) $challenge['user_id'] !== (int) $stored->user_id)) {
                throw new \RuntimeException('passkey_credential_unknown');
            }

            $record = $this->deserialize((string) $stored->credential_record, CredentialRecord::class);
            $options = $this->deserialize((string) $challenge['options'], PublicKeyCredentialRequestOptions::class);
            $validated = AuthenticatorAssertionResponseValidator::create($this->ceremonyFactory($origin)->requestCeremony())
                ->check($record, $credential->response, $options, $rpId, $record->userHandle);
            $userVerified = $credential->response->authenticatorData->isUserVerified();

            if ($purpose === 'login' && ! $userVerified) {
                throw new \RuntimeException('passkey_user_verification_required');
            }

            $transaction = $purpose === 'login' ? Str::random(64) : null;
            $verifiedAt = now();
            $expiresAt = $verifiedAt->copy()->addSeconds(self::AUTHENTICATION_EVIDENCE_TTL_SECONDS);
            $saved = $stored->forceFill([
                'credential_record' => $this->serializer()->serialize($validated, 'json'),
                'signature_counter' => $validated->counter,
                'backup_eligible' => $validated->backupEligible,
                'backup_status' => $validated->backupStatus,
                'last_used_at' => $verifiedAt,
                'authentication_transaction_hash' => $transaction === null ? null : hash('sha256', $transaction),
                'authentication_purpose' => $transaction === null ? null : 'login',
                'authentication_verified_at' => $transaction === null ? null : $verifiedAt,
                'authentication_expires_at' => $transaction === null ? null : $expiresAt,
                'authentication_consumed_at' => null,
            ])->save();

            if ($saved !== true) {
                throw new \RuntimeException('passkey_credential_state_persist_failed');
            }

            $user = User::query()->find($stored->user_id);
            if (! $user) {
                throw new \RuntimeException('passkey_user_unknown');
            }

            $evidence = $transaction === null ? null : new VerifiedPasskeyAuthentication(
                (int) $stored->getKey(), (int) $user->getKey(), $transaction, $verifiedAt, $expiresAt,
                $userVerified,
            );

            return new PasskeyAuthenticationResult(
                $user,
                $stored,
                hash('sha256', $challenge['challenge_id'].'\0'.$stored->credential_id_hash),
                $evidence,
            );
        });
    }

    public function issueReauthentication(User $user, string $sessionId, string $userAgent): string
    {
        return $this->totp->issueTrustedEnrollmentReauthentication($user, $sessionId, $userAgent);
    }

    /** @return array<int, array<string, mixed>> */
    public function credentials(User $user): array
    {
        return PasskeyCredential::query()->where('user_id', $user->getKey())->orderBy('id')->get()
            ->map(static fn (PasskeyCredential $credential): array => [
                'id' => $credential->getKey(),
                'name' => $credential->name,
                'created_at' => $credential->created_at?->toIso8601String(),
                'last_used_at' => $credential->last_used_at?->toIso8601String(),
            ])->all();
    }

    public function rename(User $user, int $id, string $name): PasskeyCredential
    {
        $this->assertAvailable();
        $name = trim($name);
        if ($name === '') {
            throw new \RuntimeException('passkey_name_invalid');
        }
        $credential = PasskeyCredential::query()->whereKey($id)->where('user_id', $user->getKey())->firstOrFail();
        $credential->forceFill(['name' => Str::limit($name, 100, '')])->save();

        return $credential;
    }

    public function delete(User $user, int $id, string $reauthToken, string $sessionId, string $userAgent): void
    {
        $this->assertAvailable();
        try {
            $this->totp->assertReauthentication($user, $reauthToken, $sessionId, $userAgent);
        } catch (ReauthenticationRequiredException $exception) {
            throw PasskeyManagementException::for('passkey_reauthentication_required', $exception);
        }

        DB::transaction(function () use ($user, $id): void {
            $credential = PasskeyCredential::query()->whereKey($id)->where('user_id', $user->getKey())->lockForUpdate()->first();
            if (! $credential) {
                throw PasskeyManagementException::for('passkey_credential_unavailable');
            }
            $otherPasskey = PasskeyCredential::query()->where('user_id', $user->getKey())->where('id', '!=', $id)->exists();
            $totp = SocialLoginTotp::query()->where('user_id', $user->getKey())->whereNotNull('enabled_at')->exists();
            $socialOnly = SocialAccount::query()->where('user_id', $user->getKey())->exists();
            if (! $otherPasskey && ! $totp && ($socialOnly || blank($user->password))) {
                throw PasskeyManagementException::for('passkey_last_authenticator');
            }
            $credential->delete();
        });
    }

    private function assertAvailable(): void
    {
        if (! $this->enabled()) {
            throw new \RuntimeException('passkey_disabled');
        }
    }

    private function assertPurposeEnabled(string $purpose): void
    {
        $allowed = match ($purpose) {
            'login' => $this->loginEnabled(),
            'social' => $this->substitutionEnabled(),
            'reauth' => $this->enabled(),
            default => false,
        };
        if (! $allowed) {
            throw new \RuntimeException('passkey_purpose_disabled');
        }
    }

    private function userVerification(): string
    {
        $value = (string) $this->settings->get(self::IDENTIFIER, 'passkey_user_verification', 'required');

        return in_array($value, ['required', 'preferred', 'discouraged'], true) ? $value : 'required';
    }

    /** @return array{0: string, 1: string} */
    private function relyingParty(): array
    {
        $url = (string) config('app.url');
        $parts = parse_url($url);
        if (($parts['scheme'] ?? null) !== 'https' || ! is_string($parts['host'] ?? null) || $parts['host'] === '') {
            throw new \RuntimeException('passkey_https_required');
        }
        $origin = 'https://'.$parts['host'].(isset($parts['port']) ? ':'.(int) $parts['port'] : '');

        return [$parts['host'], $origin];
    }

    private function userHandleFor(User $user): string
    {
        $existing = PasskeyCredential::query()->where('user_id', $user->getKey())->value('user_handle');

        return is_string($existing) && $existing !== '' ? $existing : $this->base64UrlEncode(random_bytes(32));
    }

    /** @return CredentialRecord[] */
    private function credentialsForUser(User $user): array
    {
        return PasskeyCredential::query()->where('user_id', $user->getKey())->get()
            ->map(fn (PasskeyCredential $credential): CredentialRecord => $this->deserialize($credential->credential_record, CredentialRecord::class))
            ->all();
    }

    /** @return array<string, mixed> */
    private function storeChallenge(string $purpose, object $options, string $sessionId, string $userAgent, array $bindings): array
    {
        if ($sessionId === '') {
            throw new \RuntimeException('passkey_session_required');
        }
        $id = Str::random(48);
        $expiresAt = now()->addSeconds(self::CHALLENGE_TTL_SECONDS);
        $stored = Cache::put($this->challengeKey($id), array_merge($bindings, [
            'challenge_id' => $id,
            'purpose' => $purpose,
            'session_hash' => hash('sha256', $sessionId),
            'browser_hash' => hash('sha256', $userAgent),
            'options' => $this->serializer()->serialize($options, 'json'),
        ]), $expiresAt);
        if (! $stored) {
            throw new \RuntimeException('passkey_challenge_store_failed');
        }

        return [
            'challenge_id' => $id,
            'publicKey' => json_decode($this->serializer()->serialize($options, 'json'), true, 512, JSON_THROW_ON_ERROR),
            'expires_at' => $expiresAt->toIso8601String(),
        ];
    }

    /** @return array<string, mixed> */
    private function consumeChallenge(string $id, string $purpose, string $sessionId, string $userAgent): array
    {
        $key = $this->challengeKey($id);
        $lock = Cache::lock($key.':lock', 10);
        if (! $lock->get()) {
            throw new \RuntimeException('passkey_challenge_locked');
        }
        try {
            $challenge = Cache::pull($key);
            if (! is_array($challenge)
                || ($challenge['purpose'] ?? null) !== $purpose
                || ! hash_equals((string) ($challenge['session_hash'] ?? ''), hash('sha256', $sessionId))
                || ! hash_equals((string) ($challenge['browser_hash'] ?? ''), hash('sha256', $userAgent))
            ) {
                throw new \RuntimeException('passkey_challenge_invalid');
            }

            return $challenge;
        } finally {
            $lock->release();
        }
    }

    private function loadCredential(array $payload): PublicKeyCredential
    {
        $credential = $this->deserialize(json_encode($payload, JSON_THROW_ON_ERROR), PublicKeyCredential::class);
        if (! $credential instanceof PublicKeyCredential) {
            throw new \RuntimeException('passkey_payload_invalid');
        }

        return $credential;
    }

    private function ceremonyFactory(string $origin): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins([$origin]);

        return $factory;
    }

    private function serializer(): SerializerInterface
    {
        return $this->serializer ??= (new WebauthnSerializerFactory(
            new AttestationStatementSupportManager([new NoneAttestationStatementSupport()])
        ))->create();
    }

    private function deserialize(string $json, string $class): object
    {
        return $this->serializer()->deserialize($json, $class, 'json');
    }

    private function challengeKey(string $id): string
    {
        return self::CACHE_PREFIX.'challenge:'.hash('sha256', $id);
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $value): string
    {
        $padding = (4 - strlen($value) % 4) % 4;
        $decoded = base64_decode(strtr($value.str_repeat('=', $padding), '-_', '+/'), true);
        if ($decoded === false) {
            throw new \RuntimeException('passkey_encoding_invalid');
        }

        return $decoded;
    }
}
