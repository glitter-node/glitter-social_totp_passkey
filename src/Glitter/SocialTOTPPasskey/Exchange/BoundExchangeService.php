<?php

namespace Glitter\SocialTOTPPasskey\Exchange;

use App\Models\User;
use Carbon\CarbonInterface;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;
use Glitter\SocialTOTPPasskey\Models\SocialLoginExchange;
use Glitter\SocialTOTPPasskey\Support\RedirectPath;

/**
 * 최종 인증 교환코드의 DB-backed one-time 경계입니다.
 *
 * 평문 code와 browser binding은 저장하지 않습니다. consume은 조회 후 삭제가
 * 아니라 조건부 UPDATE 한 번으로 수행하여 동시 요청 중 하나만 승리하게 합니다.
 */
final class BoundExchangeService
{
    private const TTL_SECONDS = 60;

    private const CLEANUP_LIMIT = 50;

    public function issue(User $user, string $sessionBinding, string $redirectPath): string
    {
        if ($sessionBinding === '') {
            throw new \RuntimeException('social_totp_passkey_exchange_binding_missing');
        }

        $this->cleanupExpired();

        return $this->issueRecord($user, $sessionBinding, $redirectPath);
    }

    public function issueAfterSecondFactor(
        User $user,
        string $sessionBinding,
        string $redirectPath,
        string $challengeId,
        CarbonInterface $verifiedAt,
    ): string {
        if ($sessionBinding === '' || $challengeId === '' || $verifiedAt->isFuture()) {
            throw new \RuntimeException('social_totp_passkey_two_factor_exchange_invalid');
        }

        return $this->issueRecord(
            $user,
            $sessionBinding,
            $redirectPath,
            $this->hash($challengeId),
            $verifiedAt,
        );
    }

    private function issueRecord(
        User $user,
        string $sessionBinding,
        string $redirectPath,
        ?string $challengeHash = null,
        ?CarbonInterface $verifiedAt = null,
    ): string {
        $this->cleanupExpired();

        $code = Str::random(48);
        SocialLoginExchange::create([
            'code_hash' => $this->hash($code),
            'user_id' => $user->getKey(),
            'session_binding_hash' => $this->hash($sessionBinding),
            'redirect_path' => RedirectPath::sanitize($redirectPath),
            'expires_at' => now()->addSeconds(self::TTL_SECONDS),
            'consumed_at' => null,
            'second_factor_verified_at' => $verifiedAt,
            'second_factor_challenge_hash' => $challengeHash,
        ]);

        return $code;
    }

    /**
     * Consume-on-attempt semantics입니다. User eligibility 또는 token 생성이
     * 뒤에서 실패해도 code를 되살리지 않아 credential replay를 허용하지 않습니다.
     */
    public function consume(string $code, string $sessionBinding): ?SocialLoginExchange
    {
        if ($code === '' || $sessionBinding === '') {
            return null;
        }

        $codeHash = $this->hash($code);
        $now = now();
        $existing = SocialLoginExchange::query()
            ->where('code_hash', $codeHash)
            ->first();

        if (! $existing) {
            $this->logConsumeFailure('code_not_found');

            return null;
        }

        if ($existing->consumed_at !== null) {
            $this->logConsumeFailure('already_consumed');

            return null;
        }

        if ($existing->expires_at !== null && $existing->expires_at->lt($now)) {
            $this->logConsumeFailure('expired');

            return null;
        }

        if (! hash_equals((string) $existing->session_binding_hash, $this->hash($sessionBinding))) {
            $this->logConsumeFailure('session_binding_mismatch');

            return null;
        }

        $affected = SocialLoginExchange::query()
            ->where('code_hash', $codeHash)
            ->whereNull('consumed_at')
            ->where('expires_at', '>=', $now)
            ->where('session_binding_hash', $this->hash($sessionBinding))
            ->update([
                'consumed_at' => $now,
                'updated_at' => $now,
            ]);

        if ($affected !== 1) {
            // The conditional UPDATE remains authoritative. A concurrent request
            // may have consumed the row after the diagnostic preflight above.
            $this->logConsumeFailure('atomic_consume_race');

            return null;
        }

        return SocialLoginExchange::query()
            ->where('code_hash', $codeHash)
            ->whereNotNull('consumed_at')
            ->first();
    }

    private function cleanupExpired(): void
    {
        $ids = SocialLoginExchange::query()
            ->where('expires_at', '<', now())
            ->orderBy('id')
            ->limit(self::CLEANUP_LIMIT)
            ->pluck('id');

        if ($ids->isNotEmpty()) {
            SocialLoginExchange::query()->whereIn('id', $ids)->delete();
        }
    }

    private function hash(string $value): string
    {
        return hash('sha256', $value);
    }

    private function logConsumeFailure(string $reason): void
    {
        Log::channel('glitter_social_totp_passkey')->notice('glitter-social_totp_passkey: exchange consume rejected', [
            'action' => 'exchange_consume',
            'reason' => $reason,
        ]);
    }
}
