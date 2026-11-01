<?php

namespace Glitter\SocialTOTPPasskey\Providers;

use App\Extension\BasePluginServiceProvider;
use Glitter\SocialTOTPPasskey\Services\CoreExtensionCacheVersionInvalidator;
use Glitter\SocialTOTPPasskey\Support\ExtensionCacheVersionInvalidator;
use Glitter\SocialTOTPPasskey\Support\ProviderOrderChangeTracker;
use Glitter\SocialTOTPPasskey\Support\SocialLoginRateLimiters;

class SocialTOTPPasskeyServiceProvider extends BasePluginServiceProvider
{
    protected string $pluginIdentifier = 'glitter-social_totp_passkey';

    public function register(): void
    {
        parent::register();

        $this->app->scoped(
            ProviderOrderChangeTracker::class,
            static fn (): ProviderOrderChangeTracker => new ProviderOrderChangeTracker(),
        );
        $this->app->bind(ExtensionCacheVersionInvalidator::class, CoreExtensionCacheVersionInvalidator::class);

        $logging = require dirname(__DIR__, 4).'/config/logging.php';
        $channel = $logging['channels']['glitter_social_totp_passkey'] ?? null;
        if (! is_array($channel)) {
            throw new \RuntimeException('Invalid glitter-social_totp_passkey logging channel configuration.');
        }
        $this->app->make('config')->set('logging.channels.glitter_social_totp_passkey', $channel);
    }

    public function boot(): void
    {
        parent::boot();

        SocialLoginRateLimiters::register();
    }

    protected function loadExtensionTranslations(): void
    {
        $this->loadTranslationsFrom(
            dirname(__DIR__, 4).'/lang',
            $this->translationNamespace(),
        );
    }
}
