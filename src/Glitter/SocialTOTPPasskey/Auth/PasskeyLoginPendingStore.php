<?php

namespace Glitter\SocialTOTPPasskey\Auth;

use App\Models\User;
use Carbon\CarbonImmutable;
use Glitter\SocialTOTPPasskey\Models\PasskeyCredential;
use Glitter\SocialTOTPPasskey\Passkey\VerifiedPasskeyAuthentication;
use Illuminate\Cache\ArrayLock;
use Illuminate\Cache\NoLock;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Str;

final class PasskeyLoginPendingStore
{
    private const VERSION = 1;

    private const KEY_PREFIX = 'glitter_social_totp_passkey:passkey-login-totp:';

    private const LOCK_SECONDS = 30;

    public function __construct(private readonly SocialTotpService $totp) {}

    /** @return array{pending_id: string, expires_at: string} */
    public function create(
        VerifiedPasskeyAuthentication $authentication,
        string $sessionId,
        string $userAgent,
    ): array {
        if ($authentication->purpose() !== 'login'
            || ! $authentication->isUserVerified()
            || $authentication->userId() === null
            || $authentication->userId() < 1
            || $authentication->credentialId() < 1
            || strlen($authentication->transaction()) !== 64
            || $authentication->expiresAt()->getTimestamp() <= now()->getTimestamp()
            || $sessionId === ''
            || $userAgent === ''
        ) {
            throw PasskeyLoginException::for('passkey_verification_failed');
        }

        try {
            $encrypted = Crypt::encryptString(json_encode([
                'version' => self::VERSION,
                'user_id' => $authentication->userId(),
                'credential_id' => $authentication->credentialId(),
                'purpose' => 'login',
                'user_verified' => $authentication->isUserVerified(),
                'transaction' => $authentication->transaction(),
                'verified_at' => $authentication->verifiedAt()->getTimestamp(),
                'expires_at' => $authentication->expiresAt()->getTimestamp(),
                'session_hash' => hash('sha256', $sessionId),
                'browser_hash' => hash('sha256', $userAgent),
            ], JSON_THROW_ON_ERROR));

            $pendingId = Str::random(48);
            $stored = Cache::put($this->pendingKey($pendingId), [
                'version' => self::VERSION,
                'state' => 'active',
                'expires_at' => $authentication->expiresAt()->getTimestamp(),
                'payload' => $encrypted,
            ], $authentication->expiresAt());
        } catch (\Throwable $exception) {
            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable', $exception);
        }

        if (! $stored) {
            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable');
        }

        return [
            'pending_id' => $pendingId,
            'expires_at' => $authentication->expiresAt()->format(DATE_ATOM),
        ];
    }

    public function verifyAndClaim(
        string $pendingId,
        string $code,
        string $sessionId,
        string $userAgent,
    ): VerifiedPasskeyAuthentication {
        $this->assertPendingIdentifier($pendingId);

        $lock = $this->lock($pendingId);
        $acquired = false;

        try {
            if (! $lock->get()) {
                throw PasskeyLoginException::for('passkey_login_in_progress');
            }
            $acquired = true;

            $record = $this->activeRecord($pendingId);
            $payload = $this->decryptPayload($record);
            $this->assertPayload($payload, $sessionId, $userAgent);

            if (! $this->evidenceExists($payload)) {
                $this->storeTombstone($pendingId, (int) $payload['expires_at']);
                throw PasskeyLoginException::for('passkey_login_stale');
            }

            $user = User::query()->find((int) $payload['user_id']);
            if (! $user) {
                $this->storeTombstone($pendingId, (int) $payload['expires_at']);
                throw PasskeyLoginException::for('passkey_login_unavailable');
            }

            try {
                $counter = $this->totp->verifyForLogin($user, $code);
            } catch (\Throwable $exception) {
                throw PasskeyLoginException::for('passkey_login_temporarily_unavailable', $exception);
            }

            if ($counter === null) {
                throw PasskeyLoginException::for('passkey_totp_invalid');
            }

            if (! $this->isOwned($lock)) {
                throw PasskeyLoginException::for('passkey_login_temporarily_unavailable');
            }

            $this->storeTombstone($pendingId, (int) $payload['expires_at']);

            if (! $this->isOwned($lock)) {
                throw PasskeyLoginException::for('passkey_login_temporarily_unavailable');
            }

            $authentication = $this->authenticationFrom($payload);

            if (! $lock->release()) {
                throw PasskeyLoginException::for('passkey_login_temporarily_unavailable');
            }
            $acquired = false;

            return $authentication;
        } finally {
            if ($acquired) {
                $lock->release();
            }
        }
    }

    public function invalidate(string $pendingId, string $sessionId, string $userAgent): void
    {
        $this->assertPendingIdentifier($pendingId);
        $lock = $this->lock($pendingId);
        $acquired = false;

        try {
            if (! $lock->get()) {
                throw PasskeyLoginException::for('passkey_login_in_progress');
            }
            $acquired = true;

            $record = $this->activeRecord($pendingId);
            $payload = $this->decryptPayload($record);
            $this->assertPayload($payload, $sessionId, $userAgent);
            $this->storeTombstone($pendingId, (int) $payload['expires_at']);

            if (! $this->isOwned($lock)) {
                throw PasskeyLoginException::for('passkey_login_temporarily_unavailable');
            }

            if (! $lock->release()) {
                throw PasskeyLoginException::for('passkey_login_temporarily_unavailable');
            }
            $acquired = false;
        } finally {
            if ($acquired) {
                $lock->release();
            }
        }
    }

    private function lock(string $pendingId): Lock
    {
        try {
            $lock = Cache::lock($this->pendingKey($pendingId).':lock', self::LOCK_SECONDS);
        } catch (\Throwable $exception) {
            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable', $exception);
        }

        if ($lock instanceof NoLock || $lock instanceof ArrayLock
            || ! method_exists($lock, 'isOwnedByCurrentProcess')
        ) {
            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable');
        }

        return $lock;
    }

    /** @return array<string, mixed> */
    private function activeRecord(string $pendingId): array
    {
        try {
            $record = Cache::get($this->pendingKey($pendingId));
        } catch (\Throwable $exception) {
            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable', $exception);
        }

        if (! is_array($record)) {
            throw PasskeyLoginException::for('passkey_login_expired');
        }

        if (($record['state'] ?? null) !== 'active') {
            throw PasskeyLoginException::for('passkey_login_stale');
        }

        if ((int) ($record['version'] ?? 0) !== self::VERSION
            || (int) ($record['expires_at'] ?? 0) <= now()->getTimestamp()
            || ! is_string($record['payload'] ?? null)
        ) {
            throw PasskeyLoginException::for('passkey_login_expired');
        }

        return $record;
    }

    /** @param array<string, mixed> $record
     *  @return array<string, mixed>
     */
    private function decryptPayload(array $record): array
    {
        try {
            $payload = json_decode(Crypt::decryptString($record['payload']), true, 32, JSON_THROW_ON_ERROR);
        } catch (\Throwable $exception) {
            throw PasskeyLoginException::for('passkey_verification_failed', $exception);
        }

        if (! is_array($payload)) {
            throw PasskeyLoginException::for('passkey_verification_failed');
        }

        if ((int) ($payload['expires_at'] ?? 0) !== (int) $record['expires_at']) {
            throw PasskeyLoginException::for('passkey_verification_failed');
        }

        return $payload;
    }

    /** @param array<string, mixed> $payload */
    private function assertPayload(array $payload, string $sessionId, string $userAgent): void
    {
        if ((int) ($payload['version'] ?? 0) !== self::VERSION
            || ($payload['purpose'] ?? null) !== 'login'
            || ($payload['user_verified'] ?? null) !== true
            || (int) ($payload['user_id'] ?? 0) < 1
            || (int) ($payload['credential_id'] ?? 0) < 1
            || ! is_string($payload['transaction'] ?? null)
            || strlen($payload['transaction']) !== 64
            || (int) ($payload['verified_at'] ?? 0) < 1
            || (int) $payload['verified_at'] > now()->getTimestamp()
            || (int) $payload['verified_at'] > (int) ($payload['expires_at'] ?? 0)
            || (int) ($payload['expires_at'] ?? 0) <= now()->getTimestamp()
            || $sessionId === ''
            || $userAgent === ''
            || ! is_string($payload['session_hash'] ?? null)
            || ! hash_equals($payload['session_hash'], hash('sha256', $sessionId))
            || ! is_string($payload['browser_hash'] ?? null)
            || ! hash_equals($payload['browser_hash'], hash('sha256', $userAgent))
        ) {
            throw PasskeyLoginException::for('passkey_verification_failed');
        }
    }

    /** @param array<string, mixed> $payload */
    private function evidenceExists(array $payload): bool
    {
        try {
            return PasskeyCredential::query()
                ->whereKey((int) $payload['credential_id'])
                ->where('user_id', (int) $payload['user_id'])
                ->where('authentication_transaction_hash', hash('sha256', $payload['transaction']))
                ->where('authentication_purpose', 'login')
                ->whereNull('authentication_consumed_at')
                ->where('authentication_expires_at', '>=', now())
                ->exists();
        } catch (\Throwable $exception) {
            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable', $exception);
        }
    }

    /** @param array<string, mixed> $payload */
    private function authenticationFrom(array $payload): VerifiedPasskeyAuthentication
    {
        return new VerifiedPasskeyAuthentication(
            (int) $payload['credential_id'],
            (int) $payload['user_id'],
            $payload['transaction'],
            CarbonImmutable::createFromTimestamp((int) $payload['verified_at']),
            CarbonImmutable::createFromTimestamp((int) $payload['expires_at']),
            true,
        );
    }

    private function storeTombstone(string $pendingId, int $expiresAt): void
    {
        if ($expiresAt <= now()->getTimestamp()) {
            throw PasskeyLoginException::for('passkey_login_expired');
        }

        try {
            $stored = Cache::put($this->pendingKey($pendingId), [
                'version' => self::VERSION,
                'state' => 'claimed',
                'expires_at' => $expiresAt,
            ], CarbonImmutable::createFromTimestamp($expiresAt));
        } catch (\Throwable $exception) {
            $this->forgetAfterTombstoneFailure($pendingId);

            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable', $exception);
        }

        if (! $stored) {
            $this->forgetAfterTombstoneFailure($pendingId);

            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable');
        }
    }

    private function forgetAfterTombstoneFailure(string $pendingId): void
    {
        try {
            Cache::forget($this->pendingKey($pendingId));
        } catch (\Throwable) {
            // Fail closed: never return authentication after an uncertain tombstone write.
        }
    }

    private function isOwned(Lock $lock): bool
    {
        try {
            return $lock->isOwnedByCurrentProcess();
        } catch (\Throwable) {
            return false;
        }
    }

    private function assertPendingIdentifier(string $pendingId): void
    {
        if (strlen($pendingId) !== 48 || ! ctype_alnum($pendingId)) {
            throw PasskeyLoginException::for('passkey_verification_failed');
        }
    }

    private function pendingKey(string $pendingId): string
    {
        return self::KEY_PREFIX.hash('sha256', $pendingId);
    }
}
