<?php

namespace Glitter\SocialTOTPPasskey\Support;

/**
 * Naver/카카오/구글/Facebook 공식 브랜드 아이콘을 data URI로 제공한다.
 *
 * 별도 정적 자산 서빙 라우트를 만들지 않고(이 플러그인은 프론트 JS 번들이
 * 없다) `resources/images/`의 실제 파일을 그대로 base64 인코딩해 레이아웃
 * JSON의 `<img src>`에 인라인한다. 원본 파일:
 * - kakao-symbol.png: developers.kakao.com/tool/resource/login의 공식
 *   "완성형/Large" 로그인 버튼 PNG에서 말풍선 심볼 영역만 크롭 + 배경 투명화
 *   (형태·비율 변경 없음, 배경색만 제거).
 * - google.svg: 사용자가 승인한 로컬 Google SVG 원본 그대로(무변경).
 * - facebook.svg: 사용자가 승인한 로컬 Facebook SVG 원본 그대로(무변경).
 * - naver.svg: 사용자가 승인한 로컬 Naver SVG 원본 그대로(무변경).
 * - github.svg: 사용자가 승인한 로컬 GitHub SVG 원본 그대로(무변경).
 */
class BrandIcons
{
    public static function kakaoDataUri(): string
    {
        return self::dataUri('kakao-symbol.png');
    }

    public static function naverDataUri(): string
    {
        return self::dataUri('naver.svg', 'image/svg+xml');
    }

    public static function googleDataUri(): string
    {
        return self::dataUri('google.svg', 'image/svg+xml');
    }

    public static function facebookDataUri(): string
    {
        return self::dataUri('facebook.svg', 'image/svg+xml');
    }

    public static function githubDataUri(): string
    {
        return self::dataUri('github.svg', 'image/svg+xml');
    }

    private static function dataUri(string $filename, string $mimeType = 'image/png'): string
    {
        $path = __DIR__.'/../../../../resources/images/'.$filename;

        return 'data:'.$mimeType.';base64,'.base64_encode(file_get_contents($path));
    }
}
