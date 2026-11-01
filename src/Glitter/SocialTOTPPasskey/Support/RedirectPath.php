<?php

namespace Glitter\SocialTOTPPasskey\Support;

/**
 * 로그인 후 되돌아갈 경로(`redirect` 쿼리) 검증기 — 오픈 리다이렉트 방지.
 *
 * 자기 사이트 내부의 루트 상대경로만 통과시키고, 그 외 값은 예외 없이 기본값 `/` 로
 * 조용히 폴백한다: 스킴/호스트가 든 절대 URL, 프로토콜 상대 URL(`//evil.com`),
 * 브라우저가 `/` 로 정규화하는 역슬래시·제어문자 트릭(`/\evil.com`, `/<TAB>/evil.com`),
 * 평가되지 않은 레이아웃 바인딩 원문(`{{ ... }}`), OAuth 진입점/로그인 화면 자신(루프).
 *
 * 진입(redirect) → 콜백 → 교환(exchange) 응답의 세 단계가 모두 이 함수를 거친다 —
 * 한 단계만 막으면 세션/캐시 값을 거쳐 우회될 수 있기 때문이다.
 */
final class RedirectPath
{
    public const FALLBACK = '/';

    private const MAX_LENGTH = 2048;

    public static function sanitize(mixed $value): string
    {
        if (! is_string($value) || $value === '' || strlen($value) > self::MAX_LENGTH) {
            return self::FALLBACK;
        }

        // 단일 '/' 로 시작하는 루트 상대경로만 — '//host', '/\host' 는 다른 오리진으로 해석된다.
        if ($value[0] !== '/' || (isset($value[1]) && ($value[1] === '/' || $value[1] === '\\'))) {
            return self::FALLBACK;
        }

        // 역슬래시·제어문자·공백 — 브라우저 URL 파서가 제거/치환해 위 검사를 우회시킬 수 있다.
        if (preg_match('/[\\\\\x00-\x20\x7F]/', $value) === 1) {
            return self::FALLBACK;
        }

        if (str_contains($value, '{{') || str_contains($value, '}}')) {
            return self::FALLBACK;
        }

        $parts = parse_url($value);

        if ($parts === false || isset($parts['scheme']) || isset($parts['host']) || isset($parts['user'])) {
            return self::FALLBACK;
        }

        $path = $parts['path'] ?? '';

        if ($path === '/login' || str_starts_with($path, '/api/')) {
            return self::FALLBACK;
        }

        return $value;
    }
}
