<?php

namespace Glitter\SocialTOTPPasskey\Linking;

use App\Models\User;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Glitter\SocialTOTPPasskey\Auth\SocialLoginEligibility;
use Glitter\SocialTOTPPasskey\Models\SocialAccount;
use Glitter\SocialTOTPPasskey\Models\SocialLoginUserFlag;

/**
 * Social identity attach/unlink 의 DB 경계를 담당합니다.
 *
 * OAuth 호출이나 notification 같은 외부 작업은 이 service 안에서 수행하지
 * 않습니다. 호출자가 이미 준비한 provider identity에 대해서만 transaction,
 * row lock, unique conflict recovery를 적용합니다.
 */
final class SocialLinkingService
{
    public const IDENTITY_CONFLICT = 'social_totp_passkey_identity_conflict';

    public const TARGET_NOT_ELIGIBLE = 'social_totp_passkey_link_target_not_eligible';

    public const UNLINK_DELETED = 'deleted';

    public const UNLINK_NOT_FOUND = 'not_found';

    public const UNLINK_BLOCKED = 'blocked';

    public function __construct(
        private readonly SocialLoginEligibility $eligibility,
    ) {}

    /**
     * Manual link처럼 이미 존재하는 User에 attach하는 transaction wrapper입니다.
     * 동일 User에 이미 연결되어 있으면 기존 row를 반환합니다.
     */
    public function attach(User $user, string $provider, string $providerUserId, ?string $email): SocialAccount
    {
        try {
            return DB::transaction(fn () => $this->attachWithinTransaction(
                $user,
                $provider,
                $providerUserId,
                $email,
            ));
        } catch (QueryException $e) {
            if (! $this->isProviderIdentityUniqueViolation($e)) {
                throw $e;
            }

            $winner = $this->findIdentity($provider, $providerUserId);
            if ($winner && (int) $winner->user_id === (int) $user->id) {
                return $winner;
            }

            throw new \RuntimeException(self::IDENTITY_CONFLICT, 0, $e);
        }
    }

    /**
     * 신규 User provisioning transaction 안에서 사용합니다.
     * 이 메서드는 자체 transaction을 열지 않으므로 User 생성과 SocialAccount
     * attach가 같은 outer transaction에 포함됩니다.
     */
    public function attachWithinTransaction(
        User $user,
        string $provider,
        string $providerUserId,
        ?string $email,
    ): SocialAccount {
        if (trim($providerUserId) === '') {
            throw new \RuntimeException('social_totp_passkey_provider_id_invalid');
        }

        $lockedUser = User::query()
            ->whereKey($user->getKey())
            ->lockForUpdate()
            ->first();

        if (! $lockedUser) {
            throw new \RuntimeException(self::TARGET_NOT_ELIGIBLE);
        }

        $this->eligibility->assertCanLink($lockedUser);

        $existing = SocialAccount::query()
            ->where('provider', $provider)
            ->where('provider_user_id', $providerUserId)
            ->lockForUpdate()
            ->first();

        if ($existing) {
            if ((int) $existing->user_id === (int) $lockedUser->getKey()) {
                return $existing;
            }

            throw new \RuntimeException(self::IDENTITY_CONFLICT);
        }

        $account = new SocialAccount([
            'user_id' => $lockedUser->getKey(),
            'provider' => $provider,
            'provider_user_id' => $providerUserId,
            'provider_email' => $email,
            'linked_at' => now(),
        ]);
        $account->saveOrFail();

        return $account;
    }

    public function findIdentity(string $provider, string $providerUserId): ?SocialAccount
    {
        return SocialAccount::query()
            ->where('provider', $provider)
            ->where('provider_user_id', $providerUserId)
            ->first();
    }

    public function findIdentityForUpdate(string $provider, string $providerUserId): ?SocialAccount
    {
        return SocialAccount::query()
            ->where('provider', $provider)
            ->where('provider_user_id', $providerUserId)
            ->lockForUpdate()
            ->first();
    }

    /**
     * 같은 User의 중복 link는 성공 상태로 취급하고, 다른 User 연결은 충돌로
     * 구분합니다. SQLSTATE/driver code/index name을 모두 확인해 예상한 identity
     * unique violation만 recovery 대상으로 삼습니다.
     */
    public function isProviderIdentityUniqueViolation(QueryException $e): bool
    {
        $errorInfo = $e->errorInfo;
        $sqlState = (string) ($errorInfo[0] ?? '');
        $driverCode = (string) ($errorInfo[1] ?? '');
        $details = strtolower((string) ($errorInfo[2] ?? $e->getMessage()));

        return $sqlState === '23000'
            && $driverCode === '1062'
            && str_contains($details, 'social_totp_passkey_provider_user_unique');
    }

    /**
     * User row를 먼저 잠근 뒤 현재 login method를 다시 계산합니다.
     * 따라서 같은 social-only User에 대한 concurrent unlink도 직렬화됩니다.
     */
    public function unlink(User $user, string $provider): string
    {
        return DB::transaction(function () use ($user, $provider): string {
            $lockedUser = User::query()
                ->whereKey($user->getKey())
                ->lockForUpdate()
                ->first();

            if (! $lockedUser) {
                return self::UNLINK_NOT_FOUND;
            }

            $flag = SocialLoginUserFlag::query()
                ->where('user_id', $lockedUser->getKey())
                ->lockForUpdate()
                ->first();

            $accounts = SocialAccount::query()
                ->where('user_id', $lockedUser->getKey())
                ->lockForUpdate()
                ->get();

            $target = $accounts->firstWhere('provider', $provider);
            if (! $target) {
                return self::UNLINK_NOT_FOUND;
            }

            $hasRealPassword = $flag === null || (bool) $flag->has_real_password;
            if (! $hasRealPassword && $accounts->count() <= 1) {
                return self::UNLINK_BLOCKED;
            }

            $target->delete();

            return self::UNLINK_DELETED;
        });
    }

}
