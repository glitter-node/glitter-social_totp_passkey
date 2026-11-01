<?php

namespace Glitter\SocialTOTPPasskey\Listeners;

use App\Contracts\Extension\HookListenerInterface;
use App\Services\LayoutService;
use App\Services\TemplateService;
use Glitter\SocialTOTPPasskey\Support\ExtensionCacheVersionInvalidator;
use Glitter\SocialTOTPPasskey\Support\ProviderOrderChangeTracker;
use Illuminate\Support\Facades\Log;

/**
 * Social Login 설정 저장 후, 설정에 의존하는 공개 레이아웃 캐시만 무효화합니다.
 */
final class InvalidateSocialLoginLayoutCacheListener implements HookListenerInterface
{
    private const PLUGIN_ID = 'glitter-social_totp_passkey';

    /** @var array<int, string> */
    private const AFFECTED_LAYOUTS = [
        'auth/login',
        'auth/register',
        'mypage/profile',
    ];

    public function __construct(
        private readonly LayoutService $layoutService,
        private readonly TemplateService $templateService,
        private readonly ProviderOrderChangeTracker $changeTracker,
        private readonly ExtensionCacheVersionInvalidator $cacheVersionInvalidator,
    ) {}

    public static function getSubscribedHooks(): array
    {
        return [
            'core.plugin_settings.after_save' => [
                'method' => 'onSettingsSave',
                'priority' => 20,
                'type' => 'action',
                // The injected provider order is part of the cached public layout.
                // Invalidate it before the settings response returns instead of
                // waiting for the production database queue worker.
                'sync' => true,
            ],
        ];
    }

    public function handle(...$args): void {}

    /**
     * 설정 저장이 성공한 경우에만 Social Login이 주입되는 공개 레이아웃을 무효화합니다.
     *
     * @param  string  $identifier  저장된 플러그인 식별자
     * @param  array<string, mixed>  $settings  저장된 설정(값은 기록하지 않음)
     * @param  bool  $result  저장 성공 여부
     */
    public function onSettingsSave(string $identifier, array $settings, bool $result): void
    {
        if ($identifier !== self::PLUGIN_ID) {
            return;
        }

        // 저장 실패를 포함해 after-save에 도달한 모든 대상 요청에서 상태를 먼저 소비합니다.
        $providerOrderChanged = $this->changeTracker->consume(self::PLUGIN_ID);

        if ($result !== true) {
            return;
        }

        try {
            $templateIdentifier = $this->templateService->getActiveTemplateIdentifier('user');
            $template = $this->templateService->findByIdentifier($templateIdentifier);
            $templateId = (int) ($template?->id ?? 0);

            if ($templateId <= 0) {
                Log::channel('glitter_social_totp_passkey')->warning('[glitter-social_totp_passkey] 사용자 템플릿을 찾지 못해 레이아웃 캐시를 무효화하지 못했습니다.', [
                    'template_identifier' => $templateIdentifier,
                ]);

                return;
            }

            foreach (self::AFFECTED_LAYOUTS as $layoutName) {
                $this->layoutService->clearLayoutCache($templateId, $layoutName);
            }

            // 서버 레이아웃 캐시가 모두 삭제된 뒤에만 새 클라이언트 캐시 좌표를 공개합니다.
            if ($providerOrderChanged) {
                $this->cacheVersionInvalidator->invalidate();
            }
        } catch (\Throwable $e) {
            // 설정 저장은 이미 완료되었으므로 캐시 무효화 실패가 저장 결과를 되돌리지는 않습니다.
            Log::channel('glitter_social_totp_passkey')->warning('[glitter-social_totp_passkey] 설정 저장 후 레이아웃 캐시 무효화에 실패했습니다.', [
                'error' => $e->getMessage(),
            ]);
        }
    }
}
