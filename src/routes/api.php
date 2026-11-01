<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Glitter\SocialTOTPPasskey\Http\Controllers\SocialAuthController;
use Glitter\SocialTOTPPasskey\Http\Controllers\PasskeyController;
use Glitter\SocialTOTPPasskey\Services\SocialAuthService;
use Glitter\SocialTOTPPasskey\Support\SocialLoginRateLimiters;

/*
 * glitter-social_totp_passkey 플러그인 API 라우트
 *
 * URL prefix: /api/plugins/glitter-social_totp_passkey  (PluginRouteServiceProvider 자동 적용)
 *
 * 제한은 이름 있는 제한기로 건다(SocialLoginRateLimiters). 이름 없는 `throttle:N,1` 은
 * 다른 공개 API 와 카운터를 같이 써서, 둘러보기만 한 방문자도 로그인에서 막혔다.
 */

Route::get('{provider}/redirect', [SocialAuthController::class, 'redirect'])
    ->whereIn('provider', SocialAuthService::PROVIDERS)
    ->middleware(['start.api.session', 'throttle:'.SocialLoginRateLimiters::OAUTH])
    ->name('redirect');

Route::get('{provider}/callback', [SocialAuthController::class, 'callback'])
    ->whereIn('provider', SocialAuthService::PROVIDERS)
    ->middleware(['start.api.session', 'throttle:'.SocialLoginRateLimiters::OAUTH])
    ->name('callback');

Route::post('exchange', [SocialAuthController::class, 'exchange'])
    ->middleware(['start.api.session', 'throttle:'.SocialLoginRateLimiters::EXCHANGE])
    ->name('exchange');

Route::post('two-factor', [SocialAuthController::class, 'completeTwoFactor'])
    ->middleware(['start.api.session', 'throttle:'.SocialLoginRateLimiters::EXCHANGE])
    ->name('two-factor');

Route::post('passkey/authenticate/options', [PasskeyController::class, 'authenticateOptions'])
    ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::PASSKEY])
    ->name('passkey.authenticate.options');
Route::post('passkey/authenticate/verify', [PasskeyController::class, 'authenticateVerify'])
    ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::PASSKEY])
    ->name('passkey.authenticate.verify');
Route::post('passkey/authenticate/totp', [PasskeyController::class, 'completeLoginTotp'])
    ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::PASSKEY])
    ->name('passkey.authenticate.totp');

Route::post('totp/social-enrollment/identity', [SocialAuthController::class, 'completeSocialTotpEnrollmentIdentity'])
    ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::EXCHANGE])
    ->name('totp.social-enrollment.identity');
Route::post('totp/social-enrollment', [SocialAuthController::class, 'beginSocialTotpEnrollment'])
    ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::ACCOUNT])
    ->name('totp.social-enrollment');
Route::post('totp/social-enrollment/confirm', [SocialAuthController::class, 'confirmSocialTotpEnrollment'])
    ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::ACCOUNT])
    ->name('totp.social-enrollment.confirm');

// 한시적 기존 회원 전환 경로. 일반 OAuth callback/복구 경로와 분리한다.
Route::get('totp/transition/{provider}/redirect', [SocialAuthController::class, 'transitionRedirect'])
    ->whereIn('provider', SocialAuthService::PROVIDERS)
    ->middleware(['start.api.session', 'throttle:'.SocialLoginRateLimiters::OAUTH])
    ->name('totp.transition.redirect');
Route::get('totp/transition/{provider}/callback', [SocialAuthController::class, 'transitionCallback'])
    ->whereIn('provider', SocialAuthService::PROVIDERS)
    ->middleware(['start.api.session', 'throttle:'.SocialLoginRateLimiters::OAUTH])
    ->name('totp.transition.callback');
Route::post('totp/transition/enrollment', [SocialAuthController::class, 'beginTransitionEnrollment'])
    ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::ACCOUNT])
    ->name('totp.transition.enrollment');
Route::post('totp/transition/enrollment/confirm', [SocialAuthController::class, 'confirmTransitionEnrollment'])
    ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::ACCOUNT])
    ->name('totp.transition.enrollment.confirm');

Route::middleware([
    'auth:sanctum',
    'check.user_status',
    'admin',
    'throttle:'.config('auth.throttle.admin'),
    'permission:admin,'.\Glitter\SocialTOTPPasskey\Auth\SocialTotpTransitionService::PERMISSION,
])->group(function () {
    Route::get('totp/transition', [SocialAuthController::class, 'listTotpTransitions'])->name('totp.transition.index');
    Route::get('totp/transition/audits', [SocialAuthController::class, 'listTotpTransitionAudits'])->name('totp.transition.audits');
    Route::post('totp/transition/dry-run', [SocialAuthController::class, 'dryRunTotpTransition'])->middleware(['start.api.session', ValidateCsrfToken::class])->name('totp.transition.dry-run');
    Route::post('totp/transition/designate', [SocialAuthController::class, 'designateTotpTransition'])->middleware(['start.api.session', ValidateCsrfToken::class])->name('totp.transition.designate');
    Route::put('totp/transition/policy', [SocialAuthController::class, 'updateTotpTransitionPolicy'])->middleware([ValidateCsrfToken::class])->name('totp.transition.policy');
    Route::post('totp/transition/emergency-stop', [SocialAuthController::class, 'emergencyStopTotpTransition'])->middleware(['start.api.session', ValidateCsrfToken::class])->name('totp.transition.emergency-stop');
});

// 복구 요청은 OAuth callback에서만 생성된다. 관리자 승인 API는 core permission
// middleware와 서비스 내부의 동일 권한 검사를 모두 통과해야 한다.
Route::middleware(['auth:sanctum', 'check.user_status'])->group(function () {
    Route::post('passkey/reauthenticate/options', [PasskeyController::class, 'reauthenticateOptions'])
        ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::PASSKEY])
        ->name('passkey.reauthenticate.options');
    Route::post('passkey/reauthenticate/verify', [PasskeyController::class, 'reauthenticateVerify'])
        ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::PASSKEY])
        ->name('passkey.reauthenticate.verify');
    Route::post('passkey/register/options', [PasskeyController::class, 'registerOptions'])
        ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::PASSKEY])
        ->name('passkey.register.options');
    Route::post('passkey/register/verify', [PasskeyController::class, 'registerVerify'])
        ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::PASSKEY])
        ->name('passkey.register.verify');
    Route::get('passkey/credentials', [PasskeyController::class, 'credentials'])
        ->middleware('throttle:'.SocialLoginRateLimiters::PASSKEY)
        ->name('passkey.credentials');
    Route::patch('passkey/credentials/{id}', [PasskeyController::class, 'rename'])
        ->whereNumber('id')
        ->middleware([
            'start.api.session',
            ValidateCsrfToken::class,
            'throttle:'.SocialLoginRateLimiters::PASSKEY,
        ])
        ->name('passkey.credentials.rename');
    Route::delete('passkey/credentials/{id}', [PasskeyController::class, 'delete'])
        ->whereNumber('id')->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::PASSKEY])
        ->name('passkey.credentials.delete');

    Route::get('totp/recovery', [SocialAuthController::class, 'listTotpRecoveryRequests'])
        ->middleware('permission:admin,core.users.read')->name('totp.recovery.index');
    Route::post('totp/recovery/{requestId}/approve', [SocialAuthController::class, 'approveTotpRecovery'])
        ->whereNumber('requestId')->middleware(['start.api.session', ValidateCsrfToken::class, 'permission:admin,core.users.update', 'throttle:'.SocialLoginRateLimiters::ACCOUNT])
        ->name('totp.recovery.approve');
    Route::post('totp/recovery/{requestId}/reject', [SocialAuthController::class, 'rejectTotpRecovery'])
        ->whereNumber('requestId')->middleware(['start.api.session', ValidateCsrfToken::class, 'permission:admin,core.users.update', 'throttle:'.SocialLoginRateLimiters::ACCOUNT])
        ->name('totp.recovery.reject');
});

Route::post('registration', [SocialAuthController::class, 'submitRegistration'])
    ->middleware(['start.api.session', 'throttle:'.SocialLoginRateLimiters::EXCHANGE])
    ->name('registration');

Route::post('registration/idv', [SocialAuthController::class, 'completeRegistrationIdentity'])
    ->middleware(['start.api.session', 'throttle:'.SocialLoginRateLimiters::EXCHANGE])
    ->name('registration.idv');
Route::post('registration/totp', [SocialAuthController::class, 'beginRegistrationTotp'])
    ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::EXCHANGE])
    ->name('registration.totp');
Route::post('registration/totp/confirm', [SocialAuthController::class, 'completeRegistrationTotp'])
    ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::EXCHANGE])
    ->name('registration.totp.confirm');

Route::middleware(['auth:sanctum', 'check.user_status'])->group(function () {
    Route::get('accounts', [SocialAuthController::class, 'accounts'])->name('accounts');
    Route::post('totp/reauthenticate', [SocialAuthController::class, 'reauthenticateTotp'])
        ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::ACCOUNT])
        ->name('totp.reauthenticate');
    Route::post('totp/enrollment', [SocialAuthController::class, 'beginTotpEnrollment'])
        ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::ACCOUNT])
        ->name('totp.enrollment');
    Route::post('totp/enrollment/confirm', [SocialAuthController::class, 'confirmTotpEnrollment'])
        ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::ACCOUNT])
        ->name('totp.enrollment.confirm');
    Route::delete('totp', [SocialAuthController::class, 'disableTotp'])
        ->middleware(['start.api.session', ValidateCsrfToken::class, 'throttle:'.SocialLoginRateLimiters::ACCOUNT])
        ->name('totp.disable');

    // start.api.session — 연동 대상 회원을 URL 이 아니라 세션에 싣기 위해 세션을 시작한다.
    // 인증을 통과한 이 요청만 세션에 값을 쓸 수 있으므로, 남이 만든 링크로는 대상을 지정할 수 없다.
    Route::post('{provider}/link/prepare', [SocialAuthController::class, 'linkPrepare'])
        ->whereIn('provider', SocialAuthService::PROVIDERS)
        ->middleware(['start.api.session', 'throttle:'.SocialLoginRateLimiters::ACCOUNT])
        ->name('link.prepare');

    Route::delete('{provider}/unlink', [SocialAuthController::class, 'unlink'])
        ->whereIn('provider', SocialAuthService::PROVIDERS)
        ->middleware(['throttle:'.SocialLoginRateLimiters::ACCOUNT])
        ->name('unlink');
});
