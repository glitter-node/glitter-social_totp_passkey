<?php

namespace Glitter\SocialTOTPPasskey\Auth;

use App\Models\User;

/**
 * 최종 Social authentication 완료 시점의 plugin-owned 공통 side effect입니다.
 *
 * Core의 `core.auth.after_login` 전체를 발행하지 않습니다. 해당 hook은 password
 * failure counter reset과 activity logging까지 함께 실행하므로 Social OAuth 성공을
 * password credential 성공으로 오인하게 만들 수 있습니다.
 */
final class SocialAuthCompletion
{
    public function complete(User $user): void
    {
        $user->forceFill(['last_login_at' => now()])->save();
    }
}
