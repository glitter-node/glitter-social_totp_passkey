<?php

namespace Glitter\SocialTOTPPasskey\Support;

use Glitter\SocialTOTPPasskey\Services\SocialAuthService;

final class ProviderOrder
{
    /** @return array<int, string> */
    public static function normalize(mixed $value): array
    {
        if (! is_array($value)) {
            return SocialAuthService::PROVIDERS;
        }

        $normalized = [];

        foreach ($value as $provider) {
            if (! is_string($provider)
                || ! in_array($provider, SocialAuthService::PROVIDERS, true)
                || in_array($provider, $normalized, true)
            ) {
                continue;
            }

            $normalized[] = $provider;
        }

        foreach (SocialAuthService::PROVIDERS as $provider) {
            if (! in_array($provider, $normalized, true)) {
                $normalized[] = $provider;
            }
        }

        return array_values($normalized);
    }

    /** @param callable(string): bool $isEnabled */
    public static function enabled(mixed $value, callable $isEnabled): array
    {
        return array_values(array_filter(
            self::normalize($value),
            static fn (string $provider): bool => $isEnabled($provider),
        ));
    }

    /** @param array<int, string> $enabled */
    public static function mergeEnabledOrder(mixed $current, mixed $newEnabled, array $enabled): array
    {
        $fullOrder = self::normalize($current);
        $enabledSet = array_values(array_unique(array_values(array_filter(
            $enabled,
            static fn (mixed $provider): bool => is_string($provider)
                && in_array($provider, SocialAuthService::PROVIDERS, true),
        ))));
        $newOrder = [];

        if (is_array($newEnabled)) {
            foreach ($newEnabled as $provider) {
                if (is_string($provider)
                    && in_array($provider, $enabledSet, true)
                    && ! in_array($provider, $newOrder, true)
                ) {
                    $newOrder[] = $provider;
                }
            }
        }

        foreach ($fullOrder as $provider) {
            if (in_array($provider, $enabledSet, true) && ! in_array($provider, $newOrder, true)) {
                $newOrder[] = $provider;
            }
        }

        $nextEnabled = 0;
        foreach ($fullOrder as $index => $provider) {
            if (in_array($provider, $enabledSet, true) && isset($newOrder[$nextEnabled])) {
                $fullOrder[$index] = $newOrder[$nextEnabled++];
            }
        }

        return self::normalize($fullOrder);
    }
}
