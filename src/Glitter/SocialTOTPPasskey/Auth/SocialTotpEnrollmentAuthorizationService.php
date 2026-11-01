<?php

namespace Glitter\SocialTOTPPasskey\Auth;

use App\Enums\IdentityVerificationPurpose;
use App\Enums\IdentityVerificationStatus;
use App\Extension\IdentityVerification\IdentityVerificationManager;
use App\Models\User;
use App\Services\IdentityVerificationService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Glitter\SocialTOTPPasskey\Models\SocialAccount;
use Glitter\SocialTOTPPasskey\Models\SocialLoginUserFlag;

/**
 * OAuth만으로는 TOTP를 등록할 수 없도록, 별도의 신뢰된 IDV 결과를
 * 소셜 OAuth pending 상태와 결합합니다.
 *
 * 코어 기본 메일 provider는 이메일 소유 확인만 제공하므로 이 흐름에서는
 * 의도적으로 거부합니다. SMS/신원확인 등 비이메일 Login provider가 실제로
 * 등록·가용·Login purpose 지원을 하는 경우에만 진행합니다.
 */
final class SocialTotpEnrollmentAuthorizationService
{
    private const TTL_SECONDS = 300;

    private const PREFIX = 'glitter_social_totp_passkey:totp-enrollment-auth:';

    public function __construct(
        private readonly IdentityVerificationService $identity,
        private readonly IdentityVerificationManager $manager,
        private readonly SocialLoginEligibility $eligibility,
    ) {}

    /**
     * @return array{pending_id: string, challenge_id: string, provider_id: string, render_hint: string, public_payload: array, expires_at: string}
     */
    public function start(
        User $user,
        string $socialProvider,
        string $socialProviderUserId,
        string $sessionBinding,
    ): array {
        if ($socialProvider === '' || $socialProviderUserId === '' || $sessionBinding === '') {
            throw new \RuntimeException('social_totp_passkey_totp_enrollment_unavailable');
        }

        $this->eligibility->assertBaseCanAuthenticate($user);
        $flag = SocialLoginUserFlag::query()->where('user_id', $user->getKey())->first();
        if ($flag === null || $flag->has_real_password) {
            throw new \RuntimeException('social_totp_passkey_totp_enrollment_unavailable');
        }
        $linked = SocialAccount::query()
            ->where('user_id', $user->getKey())
            ->where('provider', $socialProvider)
            ->where('provider_user_id', $socialProviderUserId)
            ->exists();
        if (! $linked) {
            throw new \RuntimeException('social_totp_passkey_totp_enrollment_unavailable');
        }

        $idvProvider = $this->trustedLoginProvider();
        $challenge = $this->identity->start(
            IdentityVerificationPurpose::Login->value,
            $user,
            [
                'origin_type' => 'route',
                'origin_identifier' => 'glitter.social_totp_passkey.totp_enrollment',
                'user_agent' => substr((string) request()->userAgent(), 0, 512),
                'ip_address' => request()->ip(),
            ],
            $idvProvider->getId(),
        );

        $status = $this->identity->getStatus($challenge->id);
        if (! is_array($status)
            || ($status['purpose'] ?? null) !== IdentityVerificationPurpose::Login->value
            || ($status['provider_id'] ?? null) !== $idvProvider->getId()
            || $challenge->renderHint !== 'text_code'
            || ! in_array($status['status'] ?? null, [
                IdentityVerificationStatus::Requested->value,
                IdentityVerificationStatus::Sent->value,
                IdentityVerificationStatus::Processing->value,
            ], true)
        ) {
            $this->identity->cancel($challenge->id);
            throw new \RuntimeException('social_totp_passkey_totp_enrollment_unavailable');
        }

        $pendingId = Str::random(48);
        $expiresAt = $challenge->expiresAt ?? now()->addSeconds(self::TTL_SECONDS);
        $ttl = max(1, min(self::TTL_SECONDS, now()->diffInSeconds($expiresAt, false)));
        $stored = Cache::put($this->key($pendingId), [
            'user_id' => (int) $user->getKey(),
            'social_provider' => $socialProvider,
            'social_provider_user_id_hash' => hash('sha256', $socialProvider."\0".$socialProviderUserId),
            'session_binding_hash' => hash('sha256', $sessionBinding),
            'challenge_id' => $challenge->id,
            'provider_id' => $idvProvider->getId(),
        ], now()->addSeconds($ttl));

        if (! $stored) {
            throw new \RuntimeException('social_totp_passkey_totp_enrollment_unavailable');
        }

        return [
            'pending_id' => $pendingId,
            'challenge_id' => $challenge->id,
            'provider_id' => $idvProvider->getId(),
            'render_hint' => $challenge->renderHint,
            'public_payload' => $challenge->publicPayload,
            'expires_at' => $expiresAt->toIso8601String(),
        ];
    }

    /**
     * @param array<string, mixed> $input
     */
    public function complete(string $pendingId, string $sessionBinding, array $input): ?User
    {
        if ($pendingId === '' || $sessionBinding === '' || $input === []) {
            return null;
        }

        $key = $this->key($pendingId);
        $lock = Cache::lock($key.':lock', 10);
        if (! $lock->get()) {
            return null;
        }

        try {
            $pending = Cache::get($key);
            if (! is_array($pending)
                || ! hash_equals((string) ($pending['session_binding_hash'] ?? ''), hash('sha256', $sessionBinding))
                || ! is_string($pending['social_provider'] ?? null)
                || ($pending['social_provider'] ?? '') === ''
                || ! is_string($pending['social_provider_user_id_hash'] ?? null)
                || ! preg_match('/^[a-f0-9]{64}$/', $pending['social_provider_user_id_hash'])
                || ! is_string($pending['challenge_id'] ?? null)
                || ! is_string($pending['provider_id'] ?? null)
            ) {
                return null;
            }

            $status = $this->identity->getStatus($pending['challenge_id']);
            if (! is_array($status)
                || ($status['purpose'] ?? null) !== IdentityVerificationPurpose::Login->value
                || ($status['provider_id'] ?? null) !== $pending['provider_id']
            ) {
                Cache::forget($key);
                return null;
            }

            $result = $this->identity->verify($pending['challenge_id'], $input, [
                'origin_type' => 'route',
                'origin_identifier' => 'glitter.social_totp_passkey.totp_enrollment',
                'user_agent' => substr((string) request()->userAgent(), 0, 512),
                'ip_address' => request()->ip(),
            ]);
            if (! $result->success) {
                return null;
            }

            $user = $this->identity->resolveVerifiedUser(
                $pending['challenge_id'],
                IdentityVerificationPurpose::Login->value,
            );
            if (! $user || (int) $user->getKey() !== (int) ($pending['user_id'] ?? 0)) {
                Cache::forget($key);
                return null;
            }

            $this->eligibility->assertBaseCanAuthenticate($user);
            $flag = SocialLoginUserFlag::query()->where('user_id', $user->getKey())->first();
            if ($flag === null || $flag->has_real_password) {
                Cache::forget($key);
                return null;
            }

            Cache::forget($key);

            return $user;
        } catch (\Throwable) {
            return null;
        } finally {
            $lock->release();
        }
    }

    private function trustedLoginProvider(): \App\Contracts\Extension\IdentityVerificationInterface
    {
        $provider = $this->manager->resolveForPurpose(IdentityVerificationPurpose::Login->value);
        $channels = $provider->getChannels();

        if ($provider->getId() === 'g7:core.mail'
            || ! $provider->supportsPurpose(IdentityVerificationPurpose::Login->value)
            || ! $provider->isAvailable()
            || ! is_array($channels)
            || ! array_filter($channels, static fn (mixed $channel): bool => is_string($channel) && $channel !== 'email')
        ) {
            throw new \RuntimeException('social_totp_passkey_totp_enrollment_unavailable');
        }

        return $provider;
    }

    private function key(string $pendingId): string
    {
        return self::PREFIX.hash('sha256', $pendingId);
    }
}
