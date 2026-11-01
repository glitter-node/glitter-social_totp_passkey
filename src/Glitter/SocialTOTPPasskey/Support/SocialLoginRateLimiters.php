<?php

namespace Glitter\SocialTOTPPasskey\Support;

use App\Helpers\ResponseHelper;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Glitter\SocialTOTPPasskey\Services\SocialAuthService;

/**
 * 소셜 로그인 라우트 전용 이름 있는 제한기.
 *
 * 이름 없는 `throttle:30,1` 은 키가 `sha1('|'.ip)`(비로그인) 또는 `sha1(user id)` 라
 * 게시판·메뉴·위젯 같은 다른 공개 API(`throttle:600,1`)와 카운터 하나를 같이 쓴다.
 * 제한값은 키에 들어가지 않으므로, 방문자가 평범하게 둘러보기만 해도 30 문턱이 차서
 * 소셜 로그인에서 처음 429 가 났다. 이름 있는 제한기는 키가 `md5(제한기 이름 . by 값)`
 * 이라(`ThrottleRequests::handleRequestUsingNamedLimiter`) 다른 API 와 섞이지 않는다.
 *
 * 등록은 `SocialTOTPPasskeyServiceProvider::boot()` 에서 한다 — 코어 `PluginServiceProvider` 가
 * 플러그인 프로바이더를 `PluginRouteServiceProvider` 보다 먼저 등록하므로 라우트보다 앞선다.
 * 라우트 파일 안에서 등록하면 라우트 캐시가 있을 때 그 파일이 실행되지 않아 제한기가
 * 없는 채로 요청이 들어온다.
 */
class SocialLoginRateLimiters
{
    /** redirect·callback — 브라우저 페이지 이동 */
    public const OAUTH = 'glitter.social_totp_passkey.oauth';

    /** exchange — 로그인 교환코드 XHR */
    public const EXCHANGE = 'glitter.social_totp_passkey.exchange';

    /** link/prepare·unlink — 로그인 회원의 연동 XHR */
    public const ACCOUNT = 'glitter.social_totp_passkey.account';

    /** WebAuthn ceremony 시작·검증 */
    public const PASSKEY = 'glitter.social_totp_passkey.passkey';

    /** 분당 허용 횟수 */
    public const LIMITS = [
        self::OAUTH => 20,
        self::EXCHANGE => 10,
        self::ACCOUNT => 10,
        self::PASSKEY => 10,
    ];

    /** 페이지 이동이 막혔을 때 로그인 화면에 넘기는 오류 코드 */
    public const ERROR_CODE = 'too_many_attempts';

    public static function register(): void
    {
        RateLimiter::for(self::OAUTH, fn (Request $request) => Limit::perMinute(self::LIMITS[self::OAUTH])
            ->by($request->ip())
            ->response(fn () => self::loginRedirect()));

        RateLimiter::for(self::EXCHANGE, fn (Request $request) => Limit::perMinute(self::LIMITS[self::EXCHANGE])
            ->by($request->ip())
            ->response(fn (Request $request, array $headers) => self::jsonResponse($headers)));

        RateLimiter::for(self::ACCOUNT, fn (Request $request) => Limit::perMinute(self::LIMITS[self::ACCOUNT])
            ->by(self::accountKey($request))
            ->response(fn (Request $request, array $headers) => self::jsonResponse($headers)));

        RateLimiter::for(self::PASSKEY, fn (Request $request) => Limit::perMinute(self::LIMITS[self::PASSKEY])
            ->by(self::accountKey($request))
            ->response(fn (Request $request, array $headers) => self::jsonResponse($headers)));
    }

    /**
     * 연동 라우트는 auth:sanctum 뒤에 있어 회원이 항상 있다. 없으면(미들웨어 순서가 바뀐
     * 경우 등) IP 로 센다 — 접두어로 두 종류가 서로의 키를 먹지 않게 한다.
     */
    public static function accountKey(Request $request): string
    {
        $userId = $request->user()?->getAuthIdentifier();

        return $userId !== null ? 'user:'.$userId : 'ip:'.$request->ip();
    }

    /**
     * 페이지 이동은 원문 429 대신 로그인 화면의 기존 `glitter_social_totp_passkey_error` 안내로 돌려보낸다.
     * 주소는 상대 경로로 둔다.
     */
    public static function loginRedirect(): RedirectResponse
    {
        return new RedirectResponse('/login?'.http_build_query(['glitter_social_totp_passkey_error' => self::ERROR_CODE]));
    }

    /**
     * XHR 은 429 JSON 을 유지하고 메시지만 번역한다 — 코어 `auth-login` 제한기와 같은 방식.
     *
     * @param  array<string, mixed>  $headers  Retry-After·X-RateLimit-* 헤더
     */
    public static function jsonResponse(array $headers): JsonResponse
    {
        return ResponseHelper::error(
            'messages.too_many_attempts',
            429,
            null,
            ['seconds' => (int) ($headers['Retry-After'] ?? 60)],
            SocialAuthService::IDENTIFIER
        )->withHeaders($headers);
    }
}
