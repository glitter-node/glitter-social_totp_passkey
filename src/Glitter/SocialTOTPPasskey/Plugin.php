<?php

namespace Glitter\SocialTOTPPasskey;

use App\Extension\AbstractPlugin;
use App\Extension\PluginManager;
use Glitter\SocialTOTPPasskey\Listeners\InvalidateSocialLoginLayoutCacheListener;
use Glitter\SocialTOTPPasskey\Listeners\LoginPageWidgetListener;
use Glitter\SocialTOTPPasskey\Listeners\MypageProfileWidgetListener;
use Glitter\SocialTOTPPasskey\Listeners\NormalizeProviderOrderSettingsListener;
use Glitter\SocialTOTPPasskey\Listeners\NotificationExtractDataListener;
use Glitter\SocialTOTPPasskey\Listeners\PasswordChangedFlagListener;
use Glitter\SocialTOTPPasskey\Listeners\ProfileEditPasswordGateListener;

/**
 * 소셜 로그인(NAVER/카카오/구글/Facebook/GitHub) 플러그인.
 *
 * sirsoft-basic 템플릿과 코어 인증 컨트롤러는 파일 한 줄도 수정하지 않는다 —
 * 로그인/마이페이지 화면 주입은 `core.layout_extension.after_apply` 필터 훅으로,
 * 인증은 `Socialite::buildProvider()` 로 코어 `config/services.php` 를 건드리지
 * 않고 플러그인 자체 설정(DB)만으로 처리한다.
 */
class Plugin extends AbstractPlugin
{
    public function getMetadata(): array
    {
        return [
            'author' => 'Glitter.kr',
            'license' => 'MIT',
            'keywords' => ['auth', 'oauth', 'naver', 'kakao', 'google', 'facebook', 'github', 'social-login'],
        ];
    }

    public function getHookListeners(): array
    {
        $this->assertNoOriginalPluginConflict();

        return [
            LoginPageWidgetListener::class,
            MypageProfileWidgetListener::class,
            NormalizeProviderOrderSettingsListener::class,
            InvalidateSocialLoginLayoutCacheListener::class,
            NotificationExtractDataListener::class,
            PasswordChangedFlagListener::class,
            ProfileEditPasswordGateListener::class,
        ];
    }

    public function activate(): bool
    {
        $this->assertNoOriginalPluginConflict();

        return true;
    }

    private function assertNoOriginalPluginConflict(): void
    {
        $conflicts = array_values(array_intersect(
            ['glitter-social_login', 'glitter-social_login_totp'],
            PluginManager::getActivePluginIdentifiers(),
        ));

        if ($conflicts !== []) {
            throw new \RuntimeException(
                'glitter-social_totp_passkey_conflict: deactivate '.implode(', ', $conflicts).' before activating this plugin'
            );
        }
    }

    public function getAdminMenus(): array
    {
        return [
            [
                'name' => ['ko' => '소셜 TOTP 복구', 'en' => 'Social TOTP recovery'],
                'slug' => 'glitter_social_totp_passkey-totp-recovery',
                'url' => '/admin/plugins/glitter-social_totp_passkey/totp-recovery',
                'icon' => 'fas fa-shield-halved',
                'order' => 62,
            ],
            [
                'name' => ['ko' => '소셜 TOTP 전환', 'en' => 'Social TOTP transition'],
                'slug' => 'glitter_social_totp_passkey-totp-transition',
                'url' => '/admin/plugins/glitter-social_totp_passkey/totp-transition',
                'icon' => 'fas fa-user-shield',
                'order' => 63,
            ],
        ];
    }

    /**
     * 설정 저장 검증(UpdatePluginSettingsRequest)과 민감값 마스킹
     * (PluginSettingsController::maskSensitive)이 이 스키마를 직접 참조한다 —
     * config/settings/defaults.json의 frontend_schema만으로는 저장 경로가
     * 채워지지 않는다(빈 스키마 → 검증 규칙 0개 → validated()가 모든 필드를
     * 걸러내 저장 무동작, 값은 그대로인데 "성공" 응답만 오는 침묵 실패).
     */
    public function getSettingsSchema(): array
    {
        return [
            'naver_enabled' => ['type' => 'boolean'],
            'naver_client_id' => ['type' => 'string'],
            'naver_client_secret' => ['type' => 'string', 'sensitive' => true],
            'kakao_enabled' => ['type' => 'boolean'],
            'kakao_client_id' => ['type' => 'string'],
            'kakao_client_secret' => ['type' => 'string', 'sensitive' => true],
            'google_enabled' => ['type' => 'boolean'],
            'google_client_id' => ['type' => 'string'],
            'google_client_secret' => ['type' => 'string', 'sensitive' => true],
            'facebook_enabled' => ['type' => 'boolean'],
            'facebook_client_id' => ['type' => 'string'],
            'facebook_client_secret' => ['type' => 'string', 'sensitive' => true],
            'github_enabled' => ['type' => 'boolean'],
            'github_client_id' => ['type' => 'string'],
            'github_client_secret' => ['type' => 'string', 'sensitive' => true],
            'provider_order' => ['type' => 'array'],
            'passkey_enabled' => ['type' => 'boolean'],
            'passkey_login_enabled' => ['type' => 'boolean'],
            'passkey_registration_enabled' => ['type' => 'boolean'],
            'passkey_totp_substitution_enabled' => ['type' => 'boolean'],
            'passkey_login_requires_totp' => ['type' => 'boolean'],
            'passkey_user_verification' => ['type' => 'enum', 'options' => ['required', 'preferred', 'discouraged']],
            'totp_confirm_diagnostics_enabled' => ['type' => 'boolean'],
            'glitter_social_totp_passkey_registration_diagnostics_enabled' => ['type' => 'boolean'],
            'totp_transition_enabled' => ['type' => 'boolean'],
            'totp_transition_cutoff_at' => ['type' => 'string'],
            'totp_transition_start_at' => ['type' => 'string'],
            'totp_transition_end_at' => ['type' => 'string'],
            'totp_transition_max_attempts' => ['type' => 'integer'],
            'totp_transition_emergency_stop' => ['type' => 'boolean'],
        ];
    }

    public function getConfigValues(): array
    {
        return [
            'naver_enabled' => false,
            'naver_client_id' => '',
            'naver_client_secret' => '',
            'kakao_enabled' => false,
            'kakao_client_id' => '',
            'kakao_client_secret' => '',
            'google_enabled' => false,
            'google_client_id' => '',
            'google_client_secret' => '',
            'facebook_enabled' => false,
            'facebook_client_id' => '',
            'facebook_client_secret' => '',
            'github_enabled' => false,
            'github_client_id' => '',
            'github_client_secret' => '',
            'provider_order' => ['naver', 'kakao', 'google', 'facebook', 'github'],
            'passkey_enabled' => false,
            'passkey_login_enabled' => true,
            'passkey_registration_enabled' => true,
            'passkey_totp_substitution_enabled' => false,
            'passkey_login_requires_totp' => false,
            'passkey_user_verification' => 'required',
            'totp_confirm_diagnostics_enabled' => false,
            'glitter_social_totp_passkey_registration_diagnostics_enabled' => false,
            'totp_transition_enabled' => false,
            'totp_transition_cutoff_at' => '',
            'totp_transition_start_at' => '',
            'totp_transition_end_at' => '',
            'totp_transition_max_attempts' => 5,
            'totp_transition_emergency_stop' => false,
        ];
    }

    public function getPermissions(): array
    {
        return [
            'name' => ['ko' => '글리터 소셜 TOTP 패스키', 'en' => 'Glitter Social TOTP Passkey'],
            'description' => [
                'ko' => '소셜 로그인 보안 관리 권한',
                'en' => 'Social login security management permissions',
            ],
            'categories' => [
                [
                    'identifier' => 'totp_transition',
                    'name' => ['ko' => '소셜 TOTP 전환', 'en' => 'Social TOTP transition'],
                    'description' => [
                        'ko' => '사전 확정된 기존 소셜 전용 회원의 일회성 TOTP 전환 관리',
                        'en' => 'One-time TOTP transition management for an explicit social-account roster',
                    ],
                    'permissions' => [
                        [
                            'action' => 'manage',
                            'name' => ['ko' => '소셜 TOTP 전환 관리', 'en' => 'Manage social TOTP transition'],
                            'description' => [
                                'ko' => '전환 명부·정책·긴급 중지를 관리합니다.',
                                'en' => 'Manage the transition roster, policy, and emergency stop.',
                            ],
                            'type' => 'admin',
                            'roles' => ['admin'],
                        ],
                    ],
                ],
            ],
        ];
    }

    public function getNotificationDefinitions(): array
    {
        return [
            [
                'type' => 'glitter.social_totp_passkey.account_auto_linked',
                'hook_prefix' => 'glitter.social_totp_passkey',
                'name' => ['ko' => '소셜 계정 자동 연동', 'en' => 'Social account auto-linked'],
                'description' => [
                    'ko' => '다른 방법으로 가입된 계정에 소셜 로그인이 자동 연동되었을 때 발송',
                    'en' => 'Sent when a social login is auto-linked to an existing account',
                ],
                'channels' => ['mail', 'database'],
                'hooks' => ['glitter.social_totp_passkey.account.auto_linked'],
                'variables' => [
                    ['key' => 'name', 'description' => '수신자 이름'],
                    ['key' => 'app_name', 'description' => '사이트 이름'],
                    ['key' => 'provider_name', 'description' => '연동된 소셜 제공자명'],
                    ['key' => 'provider_email', 'description' => '소셜 계정 이메일'],
                ],
                'templates' => [
                    [
                        'channel' => 'mail',
                        'recipients' => [['type' => 'trigger_user']],
                        'subject' => [
                            'ko' => '[{app_name}] {provider_name} 계정이 회원님의 계정에 자동으로 연동되었습니다',
                            'en' => '[{app_name}] Your {provider_name} account was automatically linked',
                        ],
                        'body' => [
                            'ko' => '<p>{name}님, 안녕하세요.</p><p>{provider_name} 계정({provider_email})이 회원님의 {app_name} 계정에 자동으로 연동되었습니다. 본인이 아니라면 즉시 비밀번호를 변경하고 마이페이지에서 연동을 해제해주세요.</p>',
                            'en' => "<p>Hi {name},</p><p>A {provider_name} account ({provider_email}) was automatically linked to your {app_name} account. If this wasn't you, change your password immediately and unlink it from your profile page.</p>",
                        ],
                    ],
                    [
                        'channel' => 'database',
                        'recipients' => [['type' => 'trigger_user']],
                        'subject' => [
                            'ko' => '{provider_name} 계정이 자동으로 연동되었습니다',
                            'en' => 'Your {provider_name} account was automatically linked',
                        ],
                        'body' => [
                            'ko' => '{provider_name} 계정({provider_email})이 회원님의 계정에 자동으로 연동되었습니다. 본인이 아니라면 마이페이지에서 연동을 해제해주세요.',
                            'en' => "A {provider_name} account ({provider_email}) was automatically linked to your account. If this wasn't you, unlink it from your profile page.",
                        ],
                    ],
                ],
            ],
        ];
    }
}
