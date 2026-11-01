<?php

namespace Glitter\SocialTOTPPasskey\Auth;

use App\Models\User;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use App\Services\PluginSettingsService;
use Glitter\SocialTOTPPasskey\Exchange\BoundExchangeService;
use Glitter\SocialTOTPPasskey\Models\PasskeyCredential;
use Glitter\SocialTOTPPasskey\Passkey\PasskeyService;

/**
 * Social OAuth 첫 번째 인증과 G7 Login-purpose IDV를 연결합니다.
 *
     * pending record에는 OAuth credential이나 TOTP secret을 저장하지 않고,
     * 짧은 수명의 opaque id와 User/provider/session binding만 저장합니다.
 */
final class SocialTwoFactorService
{
    private const PENDING_TTL_SECONDS = 300;

    private const LOCK_SECONDS = 10;

    private const CACHE_PREFIX = 'glitter_social_totp_passkey:two-factor:';

    public const ERROR_INVALID = 'social_totp_passkey_two_factor_invalid';

    public function __construct(
        private readonly SocialLoginEligibility $eligibility,
        private readonly BoundExchangeService $exchange,
        private readonly SocialTotpService $totp,
        private readonly PluginSettingsService $settings,
    ) {}

    /**
     * @return array{pending_id: string, challenge_id: string, provider_id: string, expires_at: string}
     */
    public function start(
        User $user,
        string $provider,
        string $providerUserId,
        string $sessionBinding,
        string $redirectPath,
    ): array {
        if ($sessionBinding === '' || $provider === '' || $providerUserId === '') {
            throw new \RuntimeException(self::ERROR_INVALID);
        }

        $this->eligibility->assertBaseCanAuthenticate($user);

        if (! $this->eligibility->requiresAdditionalAuthentication($user)) {
            throw new \RuntimeException(self::ERROR_INVALID);
        }

        $hasTotp = $this->totp->isEnabled($user);
        $hasPasskey = (bool) $this->settings->get(PasskeyService::IDENTIFIER, 'passkey_enabled', false)
            && (bool) $this->settings->get(PasskeyService::IDENTIFIER, 'passkey_totp_substitution_enabled', false)
            && PasskeyCredential::query()->where('user_id', $user->getKey())->exists();

        if (! $hasTotp && ! $hasPasskey) {
            $this->logStartFailure($provider, 'totp_not_registered');
            throw new \RuntimeException(self::ERROR_INVALID);
        }

        $pendingId = Str::random(48);

        $stored = Cache::put($this->key($pendingId), [
            'user_id' => $user->getKey(),
            'provider' => $provider,
            'provider_user_id_hash' => $this->identityHash($provider, $providerUserId),
            'session_binding_hash' => hash('sha256', $sessionBinding),
            'redirect_path' => $redirectPath,
            'method' => $hasPasskey ? 'totp_or_passkey' : SocialTotpService::PROVIDER_ID,
        ], now()->addSeconds(self::PENDING_TTL_SECONDS));

        if (! $stored) {
            $this->logStartFailure($provider, 'pending_cache_put');
            throw new \RuntimeException(self::ERROR_INVALID);
        }

        return [
            'pending_id' => $pendingId,
            'challenge_id' => '',
            'provider_id' => SocialTotpService::PROVIDER_ID,
            'expires_at' => now()->addSeconds(self::PENDING_TTL_SECONDS)->toIso8601String(),
        ];
    }

    /**
     * 시작 실패의 원인을 운영 로그에서 단계별로 식별할 수 있게 합니다.
     * 인증 코드, OAuth 토큰, challenge ID, 세션 binding 원문과 예외 메시지는 기록하지 않습니다.
     *
     * @param array<string, scalar|null> $context
     */
    private function logStartFailure(
        string $provider,
        string $stage,
        ?\Throwable $exception = null,
        array $context = [],
    ): void {
        Log::channel('glitter_social_totp_passkey')->warning('glitter-social_totp_passkey: 추가 인증 시작 단계 실패', array_merge([
            'provider' => $provider,
            'stage' => $stage,
            'exception' => $exception ? get_class($exception) : null,
            'action' => 'two_factor_start',
        ], $context));
    }

    /**
     * @return string|null Assured one-time exchange code
     */
    public function complete(string $pendingId, string $sessionBinding, string $code): ?string
    {
        if ($pendingId === '' || $sessionBinding === '' || $code === '') {
            return null;
        }

        $key = $this->key($pendingId);
        $lock = Cache::lock($key.':lock', self::LOCK_SECONDS);

        if (! $lock->get()) {
            return null;
        }

        try {
            $pending = Cache::get($key);
            if (! is_array($pending) || ! $this->bindingMatches($pending, $sessionBinding)) {
                return null;
            }

            if (! is_numeric($pending['user_id'] ?? null)
                || ! is_string($pending['provider'] ?? null)
                || $pending['provider'] === ''
                || ! is_string($pending['provider_user_id_hash'] ?? null)
                || ! preg_match('/^[a-f0-9]{64}$/', $pending['provider_user_id_hash'])
            ) {
                Cache::forget($key);
                return null;
            }

            if (! in_array(($pending['method'] ?? null), [SocialTotpService::PROVIDER_ID, 'totp_or_passkey'], true)) {
                Cache::forget($key);
                return null;
            }

            $verifiedUser = User::query()->find($pending['user_id']);
            if (! $verifiedUser) {
                Cache::forget($key);
                return null;
            }

            $counter = $this->totp->verifyForLogin($verifiedUser, $code);
            if ($counter === null) {
                return null;
            }

            $this->eligibility->assertBaseCanAuthenticate($verifiedUser);

            $challengeId = $this->totp->challengeReference($verifiedUser, $counter);
            $exchangeCode = $this->exchange->issueAfterSecondFactor(
                $verifiedUser,
                $sessionBinding,
                (string) ($pending['redirect_path'] ?? '/'),
                $challengeId,
                now(),
            );

            // The challenge is already verified, so a retry cannot issue a second
            // exchange even if the cache delete is interrupted.
            Cache::forget($key);

            return $exchangeCode;
        } catch (\Throwable) {
            // provider/IDV 내부 오류와 challenge 세부정보를 외부에 노출하지 않습니다.
            return null;
        } finally {
            $lock->release();
        }
    }

    public function resolvePasskeyUser(string $pendingId, string $sessionBinding): ?User
    {
        if (! (bool) $this->settings->get(PasskeyService::IDENTIFIER, 'passkey_enabled', false)
            || ! (bool) $this->settings->get(PasskeyService::IDENTIFIER, 'passkey_totp_substitution_enabled', false)
        ) {
            return null;
        }

        $pending = Cache::get($this->key($pendingId));
        if (! is_array($pending) || ! $this->bindingMatches($pending, $sessionBinding)
            || ($pending['method'] ?? null) !== 'totp_or_passkey'
            || ! is_numeric($pending['user_id'] ?? null)
        ) {
            return null;
        }

        return User::query()->find((int) $pending['user_id']);
    }

    public function completeWithPasskey(
        string $pendingId,
        string $sessionBinding,
        User $credentialUser,
        string $challengeReference,
    ): ?string {
        $key = $this->key($pendingId);
        $lock = Cache::lock($key.':lock', self::LOCK_SECONDS);
        if (! $lock->get()) {
            return null;
        }

        try {
            $pending = Cache::get($key);
            if (! is_array($pending) || ! $this->bindingMatches($pending, $sessionBinding)
                || ($pending['method'] ?? null) !== 'totp_or_passkey'
                || (int) ($pending['user_id'] ?? 0) !== (int) $credentialUser->getKey()
            ) {
                return null;
            }

            $this->eligibility->assertBaseCanAuthenticate($credentialUser);
            $exchangeCode = $this->exchange->issueAfterSecondFactor(
                $credentialUser,
                $sessionBinding,
                (string) ($pending['redirect_path'] ?? '/'),
                $challengeReference,
                now(),
            );
            Cache::forget($key);

            return $exchangeCode;
        } catch (\Throwable) {
            return null;
        } finally {
            $lock->release();
        }
    }

    private function key(string $pendingId): string
    {
        return self::CACHE_PREFIX.hash('sha256', $pendingId);
    }

    private function bindingMatches(array $pending, string $sessionBinding): bool
    {
        $expected = $pending['session_binding_hash'] ?? null;

        return is_string($expected)
            && hash_equals($expected, hash('sha256', $sessionBinding));
    }

    private function identityHash(string $provider, string $providerUserId): string
    {
        return hash('sha256', $provider."\0".$providerUserId);
    }
}
