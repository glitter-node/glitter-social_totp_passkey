<?php

namespace Glitter\SocialTOTPPasskey\Listeners;

use App\Contracts\Extension\HookListenerInterface;
use App\Services\PluginSettingsService;
use Glitter\SocialTOTPPasskey\Support\ProviderOrder;
use Glitter\SocialTOTPPasskey\Support\ProviderOrderChangeTracker;

final class NormalizeProviderOrderSettingsListener implements HookListenerInterface
{
    private const PLUGIN_ID = 'glitter-social_totp_passkey';

    public function __construct(
        private readonly PluginSettingsService $settingsService,
        private readonly ProviderOrderChangeTracker $changeTracker,
    ) {}

    public static function getSubscribedHooks(): array
    {
        return [
            'core.plugin_settings.filter_save_data' => [
                'method' => 'normalizeProviderOrder',
                'priority' => 10,
                'type' => 'filter',
                'sync' => true,
            ],
        ];
    }

    public function handle(...$args): void {}

    public function normalizeProviderOrder(array $settings, string $identifier): array
    {
        if ($identifier !== self::PLUGIN_ID) {
            return $settings;
        }

        if (! array_key_exists('provider_order', $settings)) {
            $this->changeTracker->record(self::PLUGIN_ID, false);

            return $settings;
        }

        $previousOrder = ProviderOrder::normalize(
            $this->settingsService->get(self::PLUGIN_ID, 'provider_order'),
        );
        $nextOrder = ProviderOrder::normalize($settings['provider_order']);

        $this->changeTracker->record(self::PLUGIN_ID, $previousOrder !== $nextOrder);
        $settings['provider_order'] = $nextOrder;

        return $settings;
    }
}
