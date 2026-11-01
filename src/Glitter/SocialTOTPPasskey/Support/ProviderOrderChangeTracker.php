<?php

namespace Glitter\SocialTOTPPasskey\Support;

/**
 * 설정 저장 filter와 after-save Listener 사이에서 Provider 순서 변경 여부를 전달합니다.
 *
 * Service Provider가 request-scoped로 등록하므로 상주 worker에서도 요청 사이에 상태가
 * 남지 않습니다. consume()은 저장 실패를 포함한 after-save 처리에서 상태를 즉시 제거합니다.
 */
final class ProviderOrderChangeTracker
{
    /** @var array<string, bool> */
    private array $changes = [];

    public function record(string $identifier, bool $changed): void
    {
        $this->changes[$identifier] = $changed;
    }

    public function consume(string $identifier): bool
    {
        $changed = $this->changes[$identifier] ?? false;
        unset($this->changes[$identifier]);

        return $changed;
    }
}
