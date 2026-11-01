<?php

namespace Glitter\SocialTOTPPasskey\Listeners;

use App\Contracts\Extension\HookListenerInterface;
use Glitter\SocialTOTPPasskey\Models\SocialAccount;

/**
 * `glitter.social_totp_passkey.notification.extract_data` 필터 — `auto_linked` 알림 정의가
 * 구독하는 훅(`glitter.social_totp_passkey.account.auto_linked`)이 발화될 때, payload
 * (SocialAccount 모델)를 알림 변수 + 수신자 컨텍스트로 변환한다.
 */
class NotificationExtractDataListener implements HookListenerInterface
{
    public static function getSubscribedHooks(): array
    {
        return [
            'glitter.social_totp_passkey.notification.extract_data' => ['method' => 'extractData', 'type' => 'filter'],
        ];
    }

    /** interface 충족용 — 실제 필터 로직은 extractData()가 담당 */
    public function handle(...$args): void {}

    /**
     * @param  array  $default  기본 반환값
     * @param  string  $type  notification_definitions.type
     * @param  array  $args  doAction 에 전달된 원본 인수 — [$account]
     */
    public function extractData(array $default, string $type, array $args): array
    {
        if ($type !== 'glitter.social_totp_passkey.account_auto_linked') {
            return $default;
        }

        $account = $args[0] ?? null;

        if (! $account instanceof SocialAccount) {
            return $default;
        }

        $account->loadMissing('user');
        $user = $account->user;

        if (! $user) {
            return $default;
        }

        $providerNames = ['kakao' => '카카오', 'google' => 'Google'];

        return [
            'data' => [
                'name' => $user->name,
                'app_name' => config('app.name'),
                'provider_name' => $providerNames[$account->provider] ?? $account->provider,
                'provider_email' => $account->provider_email ?? '',
            ],
            'context' => [
                'trigger_user_id' => $user->id,
                'trigger_user' => $user,
            ],
        ];
    }
}
