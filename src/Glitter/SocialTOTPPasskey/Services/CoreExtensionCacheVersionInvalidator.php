<?php

namespace Glitter\SocialTOTPPasskey\Services;

use App\Extension\Traits\ClearsTemplateCaches;
use Glitter\SocialTOTPPasskey\Support\ExtensionCacheVersionInvalidator;

/**
 * 코어가 소유하는 ext.cache_version 쓰기 규약을 그대로 재사용하는 adapter입니다.
 */
final class CoreExtensionCacheVersionInvalidator implements ExtensionCacheVersionInvalidator
{
    use ClearsTemplateCaches;

    public function invalidate(): void
    {
        $this->incrementExtensionCacheVersion();
    }
}
