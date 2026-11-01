<?php

namespace Plugins\Glitter\SocialTotpPasskey\Upgrades;

use App\Extension\AbstractUpgradeStep;

/**
 * 1.1.0은 신규 migration과 기본 설정 병합만 사용합니다.
 *
 * PluginSettingsService가 저장값 위에 신규 기본값을 병합하므로 기존 1.0.0 설정은
 * 덮어쓰지 않습니다. Credential 테이블은 플러그인 lifecycle migration 단계에서
 * 멱등 생성됩니다.
 */
class Upgrade_1_1_0 extends AbstractUpgradeStep {}
