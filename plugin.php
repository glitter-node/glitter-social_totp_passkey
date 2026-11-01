<?php

namespace Plugins\Glitter\SocialTotpPasskey;

// 번들 상세 조회 경로는 plugin.php를 직접 로드하므로, 코어의 확장 오토로드 등록 전에
// 실제 플러그인 구현체(Glitter\SocialTOTPPasskey\Plugin)를 해석할 수 있어야 합니다.
$vendorAutoload = __DIR__.'/vendor/autoload.php';
if (is_file($vendorAutoload)) {
    require_once $vendorAutoload;
}

/**
 * Core discovery adapter. Product code lives under Glitter\\SocialTOTPPasskey.
 */
final class Plugin extends \Glitter\SocialTOTPPasskey\Plugin
{
}
