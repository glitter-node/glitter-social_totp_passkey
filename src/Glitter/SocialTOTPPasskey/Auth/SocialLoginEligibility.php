<?php

namespace Glitter\SocialTOTPPasskey\Auth;

use App\Contracts\Repositories\UserRepositoryInterface;
use App\Enums\UserStatus;
use App\Models\User;

/**
 * Social Login 이 최종 인증 단계로 진행할 수 있는지 판단합니다.
 *
     * Core 의 private AuthService 메서드를 호출하거나 복제하지 않고, 공개 User
     * status/repository contract 를 적용합니다.
 */
final class SocialLoginEligibility
{
    public const ERROR_NOT_ELIGIBLE = 'social_totp_passkey_not_eligible';

    public const ERROR_TWO_FACTOR_REQUIRED = 'social_totp_passkey_two_factor_required';

    public function __construct(
        private readonly UserRepositoryInterface $userRepository,
    ) {}

    public function assertCanAuthenticate(User $user): void
    {
        $this->assertBaseCanAuthenticate($user);

        if ($this->requiresAdditionalAuthentication($user)) {
            throw new \RuntimeException(self::ERROR_TWO_FACTOR_REQUIRED);
        }
    }

    /**
     * Status와 administrative lock만 검사합니다.
     *
     * OAuth가 첫 번째 인증 요소로 성공한 뒤 추가 IDV가 필요한 흐름에서는
     * 이 검사를 통과한 사용자를 pending authentication으로 보낼 수 있습니다.
     */
    public function assertBaseCanAuthenticate(User $user): void
    {
        if ($user->status !== UserStatus::Active->value) {
            throw new \RuntimeException(self::ERROR_NOT_ELIGIBLE);
        }

        if ($this->userRepository->isLocked($user)) {
            throw new \RuntimeException(self::ERROR_NOT_ELIGIBLE);
        }
    }

    public function requiresAdditionalAuthentication(User $user): bool
    {
        // Social OAuth is a separate authentication session. Its second factor
        // must not be disabled merely because Core password-login 2FA is off.
        return true;
    }

    /**
     * Link/unlink는 이미 인증된 사용자 작업이므로 2FA completion을 여기서
     * 요구하지 않는다. 다만 callback round-trip 중 계정이 비활성/잠금 상태가
     * 되었다면 DB identity 변경은 허용하지 않는다.
     */
    public function assertCanLink(User $user): void
    {
        if ($user->status !== UserStatus::Active->value || $this->userRepository->isLocked($user)) {
            throw new \RuntimeException(SocialLoginEligibility::ERROR_NOT_ELIGIBLE);
        }
    }

    public function assertCanCreateSocialUser(): void
    {
    }

}
