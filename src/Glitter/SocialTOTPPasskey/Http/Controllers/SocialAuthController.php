<?php

namespace Glitter\SocialTOTPPasskey\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Http\Resources\UserResource;
use App\Helpers\ResponseHelper;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Cookie;
use Glitter\SocialTOTPPasskey\Auth\SocialTwoFactorService;
use Glitter\SocialTOTPPasskey\Auth\SocialTotpService;
use Glitter\SocialTOTPPasskey\Auth\SocialTotpEnrollmentAuthorizationService;
use Glitter\SocialTOTPPasskey\Auth\SocialTotpRecoveryService;
use Glitter\SocialTOTPPasskey\Auth\SocialTotpTransitionService;
use Glitter\SocialTOTPPasskey\Auth\SocialLoginEligibility;
use Glitter\SocialTOTPPasskey\Linking\SocialLinkingService;
use Glitter\SocialTOTPPasskey\Models\SocialAccount;
use Glitter\SocialTOTPPasskey\Models\SocialLoginUserFlag;
use Glitter\SocialTOTPPasskey\Registration\SocialRegistrationService;
use Glitter\SocialTOTPPasskey\Registration\SocialRegistrationFailure;
use Glitter\SocialTOTPPasskey\Services\SocialAuthService;
use Glitter\SocialTOTPPasskey\Support\RedirectPath;

class SocialAuthController extends Controller
{
    private const SESSION_REDIRECT = 'glitter_social_totp_passkey.redirect';

    private const SESSION_LINK_NONCE = 'glitter_social_totp_passkey.link_nonce';

    private const SESSION_EXCHANGE_BINDING = 'glitter_social_totp_passkey.exchange_binding';

    private const COOKIE_EXCHANGE_BINDING = 'glitter_social_totp_passkey_exchange_binding';

    private const SESSION_SOCIAL_TOTP_REAUTH = 'glitter_social_totp_passkey.social_totp_reauth';

    private const SESSION_SOCIAL_TOTP_RECOVERY = 'glitter_social_totp_passkey.social_totp_recovery';

    private const SESSION_SOCIAL_TOTP_TRANSITION = 'glitter_social_totp_passkey.social_totp_transition';

    public function __construct(
        private readonly SocialAuthService $service,
        private readonly SocialTwoFactorService $twoFactor,
        private readonly SocialRegistrationService $registration,
        private readonly SocialTotpService $totp,
        private readonly SocialTotpEnrollmentAuthorizationService $totpEnrollmentAuthorization,
        private readonly SocialTotpRecoveryService $totpRecovery,
        private readonly SocialTotpTransitionService $totpTransition,
    ) {}

    public function transitionRedirect(Request $request, string $provider): RedirectResponse
    {
        if (! $this->totpTransition) return $this->frontendLoginError('login_failed');
        try {
            if (! $this->totpTransition->isOpen()) throw new \RuntimeException('social_totp_passkey_totp_transition_closed');
            $driver = $this->service->driverFor($provider, "/api/plugins/glitter-social_totp_passkey/totp/transition/{$provider}/callback")->enablePKCE();
            $forceParams = match ($provider) {
                'naver' => ['auth_type' => 'reprompt'],
                'kakao' => ['prompt' => 'login'],
                'google' => ['prompt' => 'login'],
                'facebook' => ['auth_type' => 'reauthorize'],
                default => [],
            };
            if ($forceParams !== []) $driver->with($forceParams);
            $binding = Str::random(64);
            $response = $driver->redirect();
            $state = (string) $request->session()->get('state', '');
            if ($state === '') throw new \RuntimeException('social_totp_passkey_totp_transition_unavailable');
            $request->session()->put(self::SESSION_SOCIAL_TOTP_TRANSITION.'.oauth', [
                'provider' => $provider, 'binding' => $binding, 'state_hash' => hash('sha256', $state), 'created_at' => now()->timestamp,
            ]);
            return $response;
        } catch (\Throwable $e) {
            Log::channel('glitter_social_totp_passkey')->notice('glitter-social_totp_passkey: TOTP transition OAuth start failed', ['provider' => $provider, 'exception' => get_class($e)]);
            return $this->frontendLoginError('login_failed');
        }
    }

    public function transitionCallback(Request $request, string $provider): RedirectResponse
    {
        $oauth = $request->session()->pull(self::SESSION_SOCIAL_TOTP_TRANSITION.'.oauth');
        if (! is_array($oauth) || ($oauth['provider'] ?? null) !== $provider || ! is_string($oauth['binding'] ?? null)
            || ! is_string($oauth['state_hash'] ?? null) || ! is_numeric($oauth['created_at'] ?? null)
            || (int) $oauth['created_at'] < now()->subSeconds(300)->timestamp
            || ! hash_equals($oauth['state_hash'], hash('sha256', (string) $request->input('state')))) {
            return $this->frontendLoginError('login_failed');
        }
        try {
            $socialUser = $this->service->driverFor($provider, "/api/plugins/glitter-social_totp_passkey/totp/transition/{$provider}/callback")->user();
            $providerUserId = $this->service->providerUserId($socialUser);
            $result = $this->totpTransition?->completeOAuth(
                $provider, $providerUserId, $oauth['binding'], $request->session()->getId(), (string) $request->userAgent(),
            );
            if (! is_array($result)) throw new \RuntimeException('social_totp_passkey_totp_transition_unavailable');
            $request->session()->put(self::SESSION_SOCIAL_TOTP_TRANSITION, [
                'transition_id' => $result['transition_id'], 'grant_token' => $result['grant_token'],
                'reauth_token' => $result['reauth_token'], 'binding' => $oauth['binding'], 'user_id' => $result['user_id'],
            ]);
            return redirect('/login?glitter_social_totp_passkey_totp_transition_setup=1');
        } catch (\Throwable $e) {
            Log::channel('glitter_social_totp_passkey')->notice('glitter-social_totp_passkey: TOTP transition OAuth failed', ['provider' => $provider, 'exception' => get_class($e)]);
            return $this->frontendLoginError('login_failed');
        }
    }

    public function beginTransitionEnrollment(Request $request): JsonResponse
    {
        if (! $this->totp || ! $this->totpTransition) return $this->totpReauthenticationRequired();
        $context = $request->session()->get(self::SESSION_SOCIAL_TOTP_TRANSITION);
        if (! is_array($context) || ! is_numeric($context['transition_id'] ?? null) || ! is_numeric($context['user_id'] ?? null)
            || ! is_string($context['grant_token'] ?? null) || ! is_string($context['reauth_token'] ?? null) || ! is_string($context['binding'] ?? null)) return $this->totpReauthenticationRequired();
        try {
            $user = $this->totpTransition->assertEnrollmentGrant((int) $context['transition_id'], $context['grant_token'], $context['binding'], $request->session()->getId(), (string) $request->userAgent());
            if ((int) $user->getKey() !== (int) $context['user_id']) throw new \RuntimeException('social_totp_passkey_totp_transition_unavailable');
            $payload = $this->totp->beginEnrollment($user, $context['reauth_token'], $request->session()->getId(), (string) $request->userAgent());
            return $this->totpNoStore(response()->json($payload));
        } catch (\Throwable) { return $this->totpReauthenticationRequired(); }
    }

    public function confirmTransitionEnrollment(Request $request): JsonResponse
    {
        if (! $this->totp || ! $this->totpTransition) return $this->totpReauthenticationRequired();
        $context = $request->session()->get(self::SESSION_SOCIAL_TOTP_TRANSITION);
        $validated = $request->validate(['enrollment_id' => ['required', 'string', 'size:48'], 'code' => ['required', 'digits:6']]);
        if (! is_array($context) || ! is_numeric($context['transition_id'] ?? null) || ! is_numeric($context['user_id'] ?? null)
            || ! is_string($context['grant_token'] ?? null) || ! is_string($context['reauth_token'] ?? null) || ! is_string($context['binding'] ?? null)) return $this->totpReauthenticationRequired();
        $user = User::query()->find((int) $context['user_id']);
        if (! $user) return $this->totpReauthenticationRequired();
        $ok = $this->totp->confirmEnrollmentWithCommit(
            $user, $context['reauth_token'], $request->session()->getId(), (string) $request->userAgent(), $validated['enrollment_id'], $validated['code'],
            fn (): bool => $this->totpTransition->consumeWithinTransaction((int) $context['transition_id'], $context['grant_token'], $context['binding'], $request->session()->getId(), (string) $request->userAgent()),
        );
        if (! $ok) return $this->totpReauthenticationRequired();
        $request->session()->forget(self::SESSION_SOCIAL_TOTP_TRANSITION);
        return $this->totpNoStore(response()->json(['redirect_url' => '/login?glitter_social_totp_passkey_totp_transition_registered=1']));
    }

    public function listTotpTransitions(Request $request): JsonResponse
    {
        $action = 'list_totp_transitions';
        $correlationId = (string) Str::uuid();

        $user = $request->user();
        if (! $user) {
            Log::channel('glitter_social_totp_passkey')->warning('glitter-social_totp_passkey: 관리자 TOTP 전환 조회 사용자 없음', [
                'action' => $action,
                'stage' => 'controller_authentication',
                'exception' => null,
                'correlation_id' => $correlationId,
            ]);

            return response()->json(['message' => __('auth.login_failed')], 403);
        }

        $stage = 'service_list';

        try {
            $data = $this->totpTransition->list($user);
            $stage = 'service_current_policy';
            $policy = $this->totpTransition->currentPolicy($user);

            return response()->json(['data' => $data, 'policy' => $policy]);
        } catch (\Throwable $e) {
            $permissionFailure = $e instanceof \RuntimeException
                && $e->getMessage() === 'social_totp_passkey_totp_transition_forbidden';

            Log::channel('glitter_social_totp_passkey')->warning('glitter-social_totp_passkey: 관리자 TOTP 전환 조회 실패', [
                'action' => $action,
                'stage' => $permissionFailure ? 'service_permission' : $stage,
                'exception' => get_class($e),
                'correlation_id' => $correlationId,
            ]);

            if ($permissionFailure) {
                return response()->json(['message' => __('auth.login_failed')], 403);
            }

            return ResponseHelper::serverError();
        }
    }

    public function dryRunTotpTransition(Request $request): JsonResponse
    {
        if (! $this->totpTransition || ! $request->user()) return response()->json(['message' => __('auth.login_failed')], 403);
        $data = $request->validate(['user_id' => ['required', 'integer', 'min:1'], 'social_account_id' => ['required', 'integer', 'min:1']]);
        try { return response()->json(['data' => $this->totpTransition->dryRun($request->user(), (int) $data['user_id'], (int) $data['social_account_id'])]); }
        catch (\Throwable) { return response()->json(['message' => __('auth.login_failed')], 422); }
    }

    public function designateTotpTransition(Request $request): JsonResponse
    {
        if (! $this->totpTransition || ! $request->user()) return response()->json(['message' => __('auth.login_failed')], 403);
        $data = $request->validate(['user_id' => ['required', 'integer', 'min:1'], 'social_account_id' => ['required', 'integer', 'min:1'], 'confirm' => ['accepted']]);
        try { $row = $this->totpTransition->designate($request->user(), (int) $data['user_id'], (int) $data['social_account_id']); return response()->json(['data' => ['id' => $row->getKey(), 'status' => $row->status]]); }
        catch (\Throwable) { return response()->json(['message' => __('auth.login_failed')], 422); }
    }

    public function updateTotpTransitionPolicy(Request $request): JsonResponse
    {
        if (! $this->totpTransition || ! $request->user()) return response()->json(['message' => __('auth.login_failed')], 403);
        $data = $request->validate(['enabled' => ['required', 'boolean'], 'cutoff_at' => ['required', 'date'], 'start_at' => ['required', 'date'], 'end_at' => ['required', 'date'], 'max_attempts' => ['required', 'integer', 'between:1,20'], 'confirm' => ['accepted']]);
        try { return response()->json(['data' => $this->totpTransition->updatePolicy($request->user(), $data)]); }
        catch (\Throwable) { return response()->json(['message' => __('auth.login_failed')], 422); }
    }

    public function emergencyStopTotpTransition(Request $request): JsonResponse
    {
        if (! $this->totpTransition || ! $request->user()) return response()->json(['message' => __('auth.login_failed')], 403);
        $data = $request->validate(['stopped' => ['required', 'boolean'], 'confirm' => ['accepted']]);
        try { $this->totpTransition->setEmergencyStop($request->user(), (bool) $data['stopped']); return response()->json(['message' => 'ok']); }
        catch (\Throwable) { return response()->json(['message' => __('auth.login_failed')], 422); }
    }

    public function listTotpTransitionAudits(Request $request): JsonResponse
    {
        if (! $this->totpTransition || ! $request->user()) return response()->json(['message' => __('auth.login_failed')], 403);
        $id = $request->integer('transition_id') ?: null;
        try { return response()->json(['data' => $this->totpTransition->audits($request->user(), $id)]); }
        catch (\Throwable) { return response()->json(['message' => __('auth.login_failed')], 403); }
    }

    public function redirect(Request $request, string $provider): RedirectResponse
    {
        try {
            $driver = $this->service->driverFor($provider);
        } catch (\RuntimeException $e) {
            return $this->frontendLoginError('provider_unavailable');
        } catch (\Throwable $e) {
            // provider exception message에는 authorization code/token 등이 포함될 수
            // 있으므로 class/action/provider만 기록한다.
            Log::channel('glitter_social_totp_passkey')->error('glitter-social_totp_passkey: OAuth provider 조립 실패', [
                'provider' => $provider,
                'exception' => get_class($e),
                'action' => 'redirect',
            ]);

            return $this->frontendLoginError('provider_unavailable');
        }

        $request->session()->put(self::SESSION_REDIRECT, RedirectPath::sanitize($request->query('redirect')));
        $binding = Str::random(64);
        $request->session()->put(self::SESSION_EXCHANGE_BINDING, $binding);

        // 연동 대상 회원은 쿼리에서 읽지 않는다. `linkPrepare`(auth:sanctum)가 이미 세션에
        // 심어둔 값만 쓴다 — 쿼리로 받으면 남이 만든 링크로 대상을 지정할 수 있게 된다.
        // 세션에 값이 없으면 그대로 로그인 흐름이다.

        // OAuth 왕복 중 session ID가 재발급되거나 session cookie가 재설정되어도
        // 같은 브라우저의 binding을 보존한다. 값 자체는 Laravel encrypted,
        // HttpOnly cookie로 전달하고 DB에는 기존처럼 hash만 저장한다.
        return $driver->redirect()->withCookie($this->exchangeBindingCookie($binding));
    }

    public function callback(Request $request, string $provider): RedirectResponse
    {
        // 진입 시 이미 검증했지만 세션 값을 그대로 믿지 않고 콜백에서도 다시 검증한다.
        $redirectAfter = RedirectPath::sanitize($request->session()->pull(self::SESSION_REDIRECT));
        $linkNonce = $request->session()->pull(self::SESSION_LINK_NONCE);

        try {
            $driver = $this->service->driverFor($provider);
            $socialUser = $driver->user();
        } catch (\Throwable $e) {
            Log::channel('glitter_social_totp_passkey')->warning('glitter-social_totp_passkey: OAuth 콜백 실패', [
                'provider' => $provider,
                'exception' => get_class($e),
                'action' => 'oauth_callback',
                'stage' => 'provider_user_fetch',
                'reason' => 'provider_callback_failed',
            ]);

            return $linkNonce
                ? $this->frontendProfileError('oauth_failed')
                : $this->frontendLoginError('oauth_failed');
        }

        if (is_string($linkNonce) && $linkNonce !== '') {
            try {
                $providerUserId = $this->service->providerUserId($socialUser);
            } catch (\RuntimeException) {
                return $this->frontendProfileError('oauth_failed');
            }

            return $this->handleLinkCallback(
                $provider,
                $linkNonce,
                $providerUserId,
                $this->service->providerProfileEmail($provider, $socialUser),
            );
        }

        // 정상 login exchange 는 OAuth 시작 시 만든 browser binding 없이는
        // User resolution/신규 signup side effect까지 진행하지 않는다.
        $binding = $this->resolveExchangeBinding($request);
        if ($binding === null) {
            $this->logOAuthLoginFailure($provider, 'browser_binding', 'browser_binding_missing');
            return $this->frontendLoginError('login_failed');
        }

        try {
            $result = $this->service->handleLogin($provider, $socialUser, $binding, $redirectAfter);
        } catch (\RuntimeException $e) {
            $this->logOAuthLoginFailure($provider, 'login_resolution', $this->oauthLoginFailureReason($e), $e);
            $key = match ($e->getMessage()) {
                'email_exists_unverified' => 'email_exists_unverified',
                SocialLoginEligibility::ERROR_TWO_FACTOR_REQUIRED => 'two_factor_required',
                default => 'login_failed',
            };

            return $this->frontendLoginError($key);
        } catch (\Throwable $e) {
            $this->logOAuthLoginFailure($provider, 'login_resolution', 'internal_error', $e);

            return $this->frontendLoginError('login_failed');
        }

        if (isset($result['pending_registration'])) {
            return redirect('/register?'.http_build_query([
                'glitter_social_totp_passkey_registration' => $result['pending_registration']['registration_id'],
            ]));
        }

        $this->logAdditionalAuthDiagnostic(
            $provider,
            'handle_login_complete',
            null,
            false,
            false,
            false,
        );

        if (($result['requires_additional_auth'] ?? false) === true) {
            $diagnosticStage = 'additional_auth_member_type_pending';
            $totpEnabled = false;
            $generalMember = false;
            $recoveryTarget = false;
            try {
                if (! $this->twoFactor || ! $this->totp) {
                    throw new \RuntimeException(SocialTwoFactorService::ERROR_INVALID);
                }

                $providerUserId = $this->service->providerUserId($socialUser);
                $diagnosticStage = 'totp_registration_check';
                $totpEnabled = $this->totp->isEnabled($result['user']);
                [$generalMember, $recoveryTarget] = $this->additionalAuthProfile(
                    $result['user'],
                    $provider,
                    $providerUserId,
                    $totpEnabled,
                );
                $this->logAdditionalAuthDiagnostic(
                    $provider,
                    'member_type_determined',
                    null,
                    $totpEnabled,
                    $generalMember,
                    $recoveryTarget,
                );
                $this->logAdditionalAuthDiagnostic(
                    $provider,
                    'totp_registration_checked',
                    null,
                    $totpEnabled,
                    $generalMember,
                    $recoveryTarget,
                );

                if (! $totpEnabled) {
                    $diagnosticStage = 'recovery_target_check';
                    $this->logAdditionalAuthDiagnostic(
                        $provider,
                        'recovery_target_checked',
                        null,
                        $totpEnabled,
                        $generalMember,
                        $recoveryTarget,
                    );

                    if ($generalMember) {
                        $this->logAdditionalAuthDiagnostic(
                            $provider,
                            'general_member_totp_required',
                            null,
                            $totpEnabled,
                            $generalMember,
                            $recoveryTarget,
                        );

                        // 일반 회원용 TOTP 등록은 Sanctum 인증과 비밀번호
                        // 재인증 토큰이 필요한 프로필 경로에서만 허용합니다.
                        // OAuth callback만으로 소셜 recovery 권한을 부여하지
                        // 않고, 기존 일반 로그인 안내로 fail-closed 합니다.
                        return $this->frontendLoginError('two_factor_required');
                    }

                    if (! $this->totpRecovery) {
                        throw new \RuntimeException(SocialTwoFactorService::ERROR_INVALID);
                    }

                    $diagnosticStage = 'start_from_oauth';
                    $this->logAdditionalAuthDiagnostic(
                        $provider,
                        'start_from_oauth_enter',
                        null,
                        $totpEnabled,
                        $generalMember,
                        $recoveryTarget,
                    );
                    $recovery = $this->totpRecovery->startFromOAuth(
                        $result['user'],
                        $provider,
                        $providerUserId,
                        $binding,
                        $request->session()->getId(),
                        (string) $request->userAgent(),
                    );
                    $this->logAdditionalAuthDiagnostic(
                        $provider,
                        'recovery_request_created',
                        null,
                        $totpEnabled,
                        $generalMember,
                        $recoveryTarget,
                    );
                    $diagnosticStage = 'session_store';
                    $request->session()->put(self::SESSION_SOCIAL_TOTP_RECOVERY, [
                        'request_id' => $recovery['request_id'],
                        'binding' => $binding,
                        'user_id' => (int) $result['user']->getKey(),
                    ]);
                    $this->logAdditionalAuthDiagnostic(
                        $provider,
                        'session_stored',
                        null,
                        $totpEnabled,
                        $generalMember,
                        $recoveryTarget,
                    );

                    $this->logAdditionalAuthDiagnostic(
                        $provider,
                        'additional_auth_redirect',
                        null,
                        $totpEnabled,
                        $generalMember,
                        $recoveryTarget,
                    );
                    return redirect('/login?'.http_build_query([
                        'glitter_social_totp_passkey_totp_enrollment' => $recovery['request_id'],
                    ]));
                }

                $diagnosticStage = 'two_factor_service_start';
                $this->logAdditionalAuthDiagnostic(
                    $provider,
                    'glitter_social_totp_passkey_two_factor_start_enter',
                    null,
                    $totpEnabled,
                    $generalMember,
                    $recoveryTarget,
                );
                $pending = $this->twoFactor->start($result['user'], $provider, $providerUserId, $binding, $redirectAfter);
            } catch (\Throwable $e) {
                $this->logAdditionalAuthDiagnostic(
                    $provider,
                    $diagnosticStage,
                    $e,
                    $totpEnabled,
                    $generalMember,
                    $recoveryTarget,
                );

                return $this->frontendLoginError('two_factor_failed');
            }

            $this->logAdditionalAuthDiagnostic(
                $provider,
                'additional_auth_redirect',
                null,
                $totpEnabled,
                $generalMember,
                $recoveryTarget,
            );
            return redirect('/login?'.http_build_query([
                'glitter_social_totp_passkey_two_factor' => $pending['pending_id'],
            ]));
        }

        // Every social login must complete plugin-owned Login-purpose 2FA.
        // Reaching this branch indicates a policy regression; fail closed
        // instead of issuing a plain exchange.
        return $this->frontendLoginError('two_factor_failed');
    }

    /**
     * 추가 인증 진단용 회원 분류입니다. 인증 판단 자체를 대체하지 않으며,
     * 원문 식별자·메시지·토큰은 로그에 남기지 않습니다.
     *
     * @return array{0:bool,1:bool}
     */
    private function additionalAuthProfile(User $user, string $provider, string $providerUserId, bool $totpEnabled): array
    {
        try {
            $flag = SocialLoginUserFlag::query()->where('user_id', $user->getKey())->first();
            $accountExists = SocialAccount::query()
                ->where('user_id', $user->getKey())
                ->where('provider', $provider)
                ->where('provider_user_id', $providerUserId)
                ->exists();

            $generalMember = $flag === null || (bool) $flag->has_real_password;
            $recoveryTarget = ! $generalMember && $accountExists && ! $totpEnabled;

            return [$generalMember, $recoveryTarget];
        } catch (\Throwable) {
            return [false, false];
        }
    }

    private function logAdditionalAuthDiagnostic(
        string $provider,
        string $stage,
        ?\Throwable $exception,
        bool $totpEnabled,
        bool $generalMember,
        bool $recoveryTarget,
    ): void {
        $errorCode = null;
        if ($exception !== null) {
            $errorCode = match ($exception->getMessage()) {
                SocialTwoFactorService::ERROR_INVALID,
                SocialLoginEligibility::ERROR_NOT_ELIGIBLE,
                SocialLoginEligibility::ERROR_TWO_FACTOR_REQUIRED,
                SocialTotpService::ERROR_REAUTH_REQUIRED,
                'social_totp_passkey_provider_id_invalid',
                'social_totp_passkey_totp_recovery_unavailable',
                'social_totp_passkey_exchange_binding_missing' => $exception->getMessage(),
                default => 'unknown',
            };
        }

        Log::channel('glitter_social_totp_passkey')->warning('glitter-social_totp_passkey: 추가 인증 진단', [
            'provider' => $provider,
            'stage' => $stage,
            'exception' => $exception ? get_class($exception) : null,
            'error_code' => $errorCode,
            'totp_enabled' => $totpEnabled,
            'general_member' => $generalMember,
            'recovery_target' => $recoveryTarget,
            'action' => 'two_factor_start',
        ]);
    }

    private function logOAuthLoginFailure(
        string $provider,
        string $stage,
        string $reason,
        ?\Throwable $exception = null,
    ): void {
        try {
            Log::channel('glitter_social_totp_passkey')->warning('glitter_social_totp_passkey: OAuth login resolution failed', [
                'provider' => $provider,
                'action' => 'oauth_login_resolution',
                'stage' => $stage,
                'reason' => $reason,
                'exception' => $exception ? get_class($exception) : null,
            ]);
        } catch (\Throwable) {
        }
    }

    private function oauthLoginFailureReason(\RuntimeException $exception): string
    {
        if ($exception instanceof SocialRegistrationFailure) {
            return match ($exception->reason) {
                SocialRegistrationFailure::REASON_PENDING_WRITE_FAILED => 'pending_registration_write_failed',
                SocialRegistrationFailure::REASON_INPUT_INVALID => 'pending_registration_input_invalid',
                default => 'pending_registration_failed',
            };
        }

        return match ($exception->getMessage()) {
            'email_exists_unverified' => 'existing_email_unverified',
            'social_totp_passkey_identity_invalid' => 'provider_identity_invalid',
            'social_totp_passkey_provider_id_invalid' => 'provider_user_id_invalid',
            'social_totp_passkey_exchange_binding_missing' => 'browser_binding_missing',
            SocialLoginEligibility::ERROR_NOT_ELIGIBLE => 'account_not_eligible',
            SocialLoginEligibility::ERROR_TWO_FACTOR_REQUIRED => 'two_factor_required',
            default => 'unknown',
        };
    }

    private function handleLinkCallback(string $provider, string $nonce, string $providerUserId, ?string $email): RedirectResponse
    {
        $userId = $this->service->consumeLinkNonce($nonce, $provider);

        if ($userId === null) {
            return $this->frontendProfileError('link_expired');
        }

        $user = User::query()->find($userId);

        if (! $user) {
            return $this->frontendProfileError('link_expired');
        }

        try {
            $this->service->linkAccount($user, $provider, $providerUserId, $email);
        } catch (\RuntimeException $e) {
            if ($e->getMessage() === SocialLinkingService::IDENTITY_CONFLICT) {
                return $this->frontendProfileError('link_taken');
            }

            return $this->frontendProfileError('link_expired');
        }

        return redirect('/mypage/profile?glitter_social_totp_passkey_link=success');
    }

    public function exchange(Request $request): JsonResponse
    {
        $validated = $request->validate(['code' => ['required', 'string', 'max:128']]);
        $binding = $this->resolveExchangeBinding($request);
        if ($binding === null) {
            return response()->json(['message' => __('auth.login_failed')], 422);
        }

        try {
            $result = $this->service->consumeExchangeCode($validated['code'], $binding);
        } catch (\RuntimeException $e) {
            if (! in_array($e->getMessage(), [
                SocialLoginEligibility::ERROR_NOT_ELIGIBLE,
                SocialLoginEligibility::ERROR_TWO_FACTOR_REQUIRED,
            ], true)) {
                throw $e;
            }

            Log::channel('glitter_social_totp_passkey')->notice('glitter-social_totp_passkey: exchange eligibility rejected', [
                'exception' => get_class($e),
                'action' => 'exchange_eligibility',
            ]);

            return response()->json(['message' => __('auth.login_failed')], 422);
        }

        if (! $result) {
            return response()->json(['message' => __('auth.login_failed')], 422);
        }

        $request->session()->forget(self::SESSION_EXCHANGE_BINDING);

        $user = $result['user'];
        $user->load(['roles.permissions']);

        return response()->json([
            'message' => __('auth.login_success'),
            'data' => (new UserResource($user))->toAuthArray($request),
            'token' => $result['token'],
            'redirect_path' => RedirectPath::sanitize($result['redirect_path']),
        ])->withCookie(cookie()->forget(self::COOKIE_EXCHANGE_BINDING));
    }

    public function completeTwoFactor(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'pending_id' => ['required', 'string', 'max:128'],
            'code' => ['required', 'string', 'min:4', 'max:16'],
        ]);
        $binding = $this->resolveExchangeBinding($request);
        if ($binding === null) {
            return response()->json(['message' => __('auth.login_failed')], 422);
        }

        if (! $this->twoFactor) {
            return response()->json(['message' => __('auth.login_failed')], 422);
        }

        $code = $this->twoFactor->complete(
            $validated['pending_id'],
            $binding,
            $validated['code'],
        );

        if (! $code) {
            return response()->json(['message' => __('auth.login_failed')], 422);
        }

        return response()->json([
            'redirect_url' => '/login?'.http_build_query(['glitter_social_totp_passkey_exchange' => $code]),
        ]);
    }

    public function completeSocialTotpEnrollmentIdentity(Request $request): JsonResponse
    {
        if (! $this->totpRecovery || ! $this->totp) {
            return $this->totpReauthenticationRequired();
        }

        $validated = $request->validate([
            'pending_id' => ['required', 'string', 'size:48'],
        ]);
        $input = $request->except(['pending_id']);
        if ($input === []) {
            return $this->totpReauthenticationRequired();
        }

        $binding = $this->resolveExchangeBinding($request);
        if ($binding === null) {
            return $this->totpReauthenticationRequired();
        }

        $ok = $this->totpRecovery->completeEvidence(
            $validated['pending_id'],
            $binding,
            $request->session()->getId(),
            (string) $request->userAgent(),
            $input,
        );
        if (! $ok) {
            return $this->totpReauthenticationRequired();
        }

        $request->session()->put(self::SESSION_SOCIAL_TOTP_RECOVERY.'.evidence_verified', true);

        return $this->totpNoStore(response()->json([
            'redirect_url' => '/login?glitter_social_totp_passkey_totp_setup=1&glitter_social_totp_passkey_totp_recovery_pending=1',
        ]));
    }

    public function beginSocialTotpEnrollment(Request $request): JsonResponse
    {
        if (! $this->totp || ! $this->totpRecovery) {
            return $this->totpReauthenticationRequired();
        }

        $recovery = $request->session()->get(self::SESSION_SOCIAL_TOTP_RECOVERY);
        if (! is_array($recovery) || ! is_string($recovery['request_id'] ?? null)
            || ! is_string($recovery['binding'] ?? null)
        ) {
            return $this->totpReauthenticationRequired();
        }

        try {
            $authorization = $this->totpRecovery->prepareEnrollment(
                $recovery['request_id'],
                $recovery['binding'],
                $request->session()->getId(),
                (string) $request->userAgent(),
            );
            $user = User::query()->find((int) ($recovery['user_id'] ?? 0));
            if (! $user) throw new \RuntimeException('social_totp_passkey_totp_recovery_unavailable');
            $request->session()->put(self::SESSION_SOCIAL_TOTP_REAUTH, [
                'user_id' => (int) $user->getKey(), 'token' => $authorization['reauth_token'],
            ]);
            $request->session()->put(self::SESSION_SOCIAL_TOTP_RECOVERY.'.grant_token', $authorization['grant_token']);
            $payload = $this->totp->beginEnrollment(
                $user,
                $authorization['reauth_token'],
                $request->session()->getId(),
                (string) $request->userAgent(),
            );
        } catch (\Throwable) {
            return $this->totpReauthenticationRequired();
        }

        return $this->totpNoStore(response()->json($payload));
    }

    public function confirmSocialTotpEnrollment(Request $request): JsonResponse
    {
        if (! $this->totp || ! $this->totpRecovery) {
            return $this->totpReauthenticationRequired();
        }

        $authorization = $request->session()->get(self::SESSION_SOCIAL_TOTP_REAUTH);
        $recovery = $request->session()->get(self::SESSION_SOCIAL_TOTP_RECOVERY);
        $validated = $request->validate([
            'enrollment_id' => ['required', 'string', 'size:48'],
            'code' => ['required', 'digits:6'],
        ]);
        if (! is_array($authorization)
            || ! is_numeric($authorization['user_id'] ?? null)
            || ! is_string($authorization['token'] ?? null)
        ) {
            return $this->totpReauthenticationRequired();
        }
        if (! is_array($recovery) || ! is_string($recovery['request_id'] ?? null)
            || ! is_string($recovery['binding'] ?? null) || ! is_string($recovery['grant_token'] ?? null)) {
            return $this->totpReauthenticationRequired();
        }

        $user = User::query()->find((int) $authorization['user_id']);
        if (! $user) {
            return $this->totpReauthenticationRequired();
        }

        $completion = $this->totpRecovery->confirmEnrollment(
            $user,
            $recovery['request_id'],
            $recovery['grant_token'],
            $recovery['binding'],
            $request->session()->getId(),
            (string) $request->userAgent(),
            $authorization['token'],
            $validated['enrollment_id'],
            $validated['code'],
        );

        if ($completion === false) {
            return $this->totpNoStore(response()->json([
                'message' => __('glitter-social_totp_passkey::messages.totp.enrollment_failed'),
            ], 422));
        }

        if ($completion !== true) {
            // TOTP는 이미 검증됐더라도 recovery grant가 소비되지 않으면 후속
            // 로그인 권한은 만들지 않고 fail-closed로 세션 권한을 폐기한다.
            $request->session()->forget([self::SESSION_SOCIAL_TOTP_REAUTH, self::SESSION_SOCIAL_TOTP_RECOVERY]);
            return $this->totpReauthenticationRequired();
        }

        $request->session()->forget([self::SESSION_SOCIAL_TOTP_REAUTH, self::SESSION_SOCIAL_TOTP_RECOVERY]);

        return $this->totpNoStore(response()->json([
            'redirect_url' => '/login?glitter_social_totp_passkey_totp_registered=1',
        ]));
    }

    public function listTotpRecoveryRequests(Request $request): JsonResponse
    {
        if (! $this->totpRecovery || ! $request->user()) return response()->json(['message' => __('auth.login_failed')], 403);
        return response()->json(['data' => $this->totpRecovery->adminList()]);
    }

    public function approveTotpRecovery(Request $request, int $requestId): JsonResponse
    {
        if (! $this->totpRecovery || ! $request->user()) return response()->json(['message' => __('auth.login_failed')], 403);
        try { $this->totpRecovery->approve($requestId, $request->user()); }
        catch (\Throwable) { return response()->json(['message' => __('auth.login_failed')], 422); }
        return response()->json(['message' => 'ok']);
    }

    public function rejectTotpRecovery(Request $request, int $requestId): JsonResponse
    {
        if (! $this->totpRecovery || ! $request->user()) return response()->json(['message' => __('auth.login_failed')], 403);
        try { $this->totpRecovery->reject($requestId, $request->user()); }
        catch (\Throwable) { return response()->json(['message' => __('auth.login_failed')], 422); }
        return response()->json(['message' => 'ok']);
    }

    public function reauthenticateTotp(Request $request): JsonResponse
    {
        if (! $this->totp || ! $request->user()) {
            return $this->totpReauthenticationRequired();
        }

        $validated = $request->validate([
            'password' => ['required', 'string', 'max:255'],
        ]);

        try {
            $token = $this->totp->reauthenticate(
                $request->user(),
                $validated['password'],
                $request->session()->getId(),
                (string) $request->userAgent(),
            );
        } catch (\Throwable) {
            return $this->totpReauthenticationRequired();
        }

        return $this->totpNoStore(response()->json(['reauth_token' => $token]));
    }

    public function beginTotpEnrollment(Request $request): JsonResponse
    {
        if (! $this->totp || ! $request->user()) {
            return $this->totpReauthenticationRequired();
        }

        $validated = $request->validate([
            'reauth_token' => ['required', 'string', 'size:64'],
            'current_code' => ['nullable', 'digits:6'],
        ]);

        try {
            $payload = $this->totp->beginEnrollment(
                $request->user(),
                $validated['reauth_token'],
                $request->session()->getId(),
                (string) $request->userAgent(),
                (string) ($validated['current_code'] ?? ''),
            );
        } catch (\Throwable) {
            return $this->totpReauthenticationRequired();
        }

        return $this->totpNoStore(response()->json($payload));
    }

    public function confirmTotpEnrollment(Request $request): JsonResponse
    {
        if (! $this->totp || ! $request->user()) {
            return $this->totpReauthenticationRequired();
        }

        $validated = $request->validate([
            'reauth_token' => ['required', 'string', 'size:64'],
            'enrollment_id' => ['required', 'string', 'size:48'],
            'code' => ['required', 'digits:6'],
        ]);

        try {
            $ok = $this->totp->confirmEnrollment(
                $request->user(),
                $validated['reauth_token'],
                $request->session()->getId(),
                (string) $request->userAgent(),
                $validated['enrollment_id'],
                $validated['code'],
            );
        } catch (\Throwable) {
            $ok = false;
        }

        return $this->totpNoStore(response()->json(
            ['message' => $ok ? __('glitter-social_totp_passkey::messages.totp.enrollment_success') : __('glitter-social_totp_passkey::messages.totp.enrollment_failed')],
            $ok ? 200 : 422,
        ));
    }

    public function disableTotp(Request $request): JsonResponse
    {
        if (! $this->totp || ! $request->user()) {
            return $this->totpReauthenticationRequired();
        }

        $validated = $request->validate([
            'reauth_token' => ['required', 'string', 'size:64'],
            'code' => ['required', 'digits:6'],
        ]);

        try {
            $ok = $this->totp->disable(
                $request->user(),
                $validated['reauth_token'],
                $request->session()->getId(),
                (string) $request->userAgent(),
                $validated['code'],
            );
        } catch (\Throwable) {
            $ok = false;
        }

        return $this->totpNoStore(response()->json(
            ['message' => $ok ? __('glitter-social_totp_passkey::messages.totp.disabled') : __('glitter-social_totp_passkey::messages.totp.disable_failed')],
            $ok ? 200 : 422,
        ));
    }

    public function submitRegistration(Request $request): JsonResponse
    {
        try {
            $validated = $request->validate([
                'pending_id' => ['required', 'string', 'max:128'],
                'name' => ['required', 'string', 'max:255'],
                'nickname' => ['nullable', 'string', 'max:50'],
                'email' => ['nullable', 'string', 'email', 'max:255'],
                'language' => ['nullable', 'string', 'in:ko,en'],
                'agree_terms' => ['accepted'],
                'agree_privacy' => ['accepted'],
            ]);
        } catch (ValidationException $e) {
            $this->logRegistrationDiagnostic('validation', SocialRegistrationFailure::REASON_INPUT_INVALID, $e);
            $this->logRegistrationFailure('request_validation', SocialRegistrationFailure::REASON_INPUT_INVALID, $e);
            throw $e;
        }

        return $this->finishRegistration($request, $validated);
    }

    public function completeRegistrationIdentity(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'pending_id' => ['required', 'string', 'max:128'],
            'code' => ['required', 'string', 'min:4', 'max:16'],
        ]);

        if (! $this->registration) {
            return response()->json(['message' => __('glitter-social_totp_passkey::messages.registration_failed')], 422);
        }

        $binding = $this->resolveExchangeBinding($request);
        if ($binding === null) {
            return response()->json(['message' => __('glitter-social_totp_passkey::messages.registration_failed')], 422);
        }

        try {
            $result = $this->registration->completeIdentityVerification(
                $validated['pending_id'],
                $binding,
                $request->session()->getId(),
                (string) $request->userAgent(),
                $validated['code'],
            );
        } catch (\Throwable $e) {
            Log::channel('glitter_social_totp_passkey')->warning('glitter-social_totp_passkey: Social signup IDV completion failed', [
                'exception' => get_class($e),
                'action' => 'registration_idv',
            ]);

            return response()->json(['message' => __('glitter-social_totp_passkey::messages.registration_failed')], 422);
        }

        if (($result['status'] ?? null) === 'totp_required') {
            return response()->json([
                'status' => 'totp_required',
                'redirect_url' => '/register?'.http_build_query([
                    'glitter_social_totp_passkey_registration' => $validated['pending_id'],
                    'glitter_social_totp_passkey_registration_totp' => '1',
                ]),
            ]);
        }

        return $this->registrationResult($result, $binding);
    }

    private function finishRegistration(Request $request, array $validated): JsonResponse
    {
        if (! $this->registration) {
            $this->logRegistrationDiagnostic('service_missing', SocialRegistrationFailure::REASON_UNKNOWN);
            $this->logRegistrationFailure('service_missing', SocialRegistrationFailure::REASON_UNKNOWN);
            return response()->json(['message' => __('glitter-social_totp_passkey::messages.registration_failed')], 500);
        }

        $binding = $this->resolveExchangeBinding($request);
        if ($binding === null) {
            $this->logRegistrationDiagnostic('binding_missing', SocialRegistrationFailure::REASON_PENDING_BINDING_MISMATCH);
            $this->logRegistrationFailure('binding_missing', SocialRegistrationFailure::REASON_PENDING_BINDING_MISMATCH);
            return response()->json(['message' => __('glitter-social_totp_passkey::messages.registration_failed')], 422);
        }

        try {
            $result = $this->registration->submit(
                $validated['pending_id'],
                $binding,
                $request->session()->getId(),
                (string) $request->userAgent(),
                $validated,
            );
        } catch (\Throwable $e) {
            $reason = $e instanceof SocialRegistrationFailure
                ? $e->reason
                : SocialRegistrationFailure::REASON_UNKNOWN;
            $stage = $this->registrationFailureStage($reason);
            $this->logRegistrationDiagnostic($stage, $reason, $e);
            $this->logRegistrationFailure($stage, $reason, $e);

            $status = $this->registrationFailureStatus($reason);

            return response()->json(['message' => __('glitter-social_totp_passkey::messages.registration_failed')], $status);
        }

        if (($result['status'] ?? null) === 'idv_required') {
            return response()->json([
                'status' => 'idv_required',
                'redirect_url' => '/register?'.http_build_query([
                    'glitter_social_totp_passkey_registration' => $validated['pending_id'],
                    'glitter_social_totp_passkey_registration_idv' => '1',
                ]),
                'challenge_id' => $result['challenge_id'],
                'expires_at' => $result['expires_at'],
            ]);
        }

        if (($result['status'] ?? null) === 'totp_required') {
            return response()->json([
                'status' => 'totp_required',
                'redirect_url' => '/register?'.http_build_query([
                    'glitter_social_totp_passkey_registration' => $validated['pending_id'],
                    'glitter_social_totp_passkey_registration_totp' => '1',
                ]),
            ]);
        }

        return $this->registrationResult($result, $binding);
    }

    private function logRegistrationDiagnostic(string $stage, string $reason, ?\Throwable $exception = null): void
    {
        try {
            if (! function_exists('g7_plugin_settings')
                || (bool) g7_plugin_settings('glitter-social_totp_passkey', 'glitter_social_totp_passkey_registration_diagnostics_enabled', false) !== true
            ) {
                return;
            }

            Log::channel('glitter_social_totp_passkey')->warning('glitter-social_totp_passkey: social registration diagnostic', [
                'action' => 'registration_submit',
                'stage' => $stage,
                'reason' => $reason,
                'exception' => $exception ? get_class($exception) : null,
            ]);
        } catch (\Throwable) {
            // Diagnostics must never alter registration behavior or its response.
        }
    }

    private function logRegistrationFailure(
        string $stage,
        string $reason,
        ?\Throwable $exception = null,
        string $action = 'registration_submit',
    ): void
    {
        try {
            Log::channel('glitter_social_totp_passkey')->warning('glitter-social_totp_passkey: social registration failure', [
                'action' => $action,
                'stage' => $stage,
                'reason' => $reason,
                'exception' => $exception ? get_class($exception) : null,
            ]);
        } catch (\Throwable) {
        }
    }

    private function registrationFailureStage(string $reason): string
    {
        return match ($reason) {
            SocialRegistrationFailure::REASON_PENDING_MISSING_OR_EXPIRED => 'pending_lookup',
            SocialRegistrationFailure::REASON_PENDING_BINDING_MISMATCH => 'pending_binding',
            SocialRegistrationFailure::REASON_PENDING_LOCK_FAILED => 'pending_lock',
            SocialRegistrationFailure::REASON_PENDING_WRITE_FAILED => 'pending_write',
            SocialRegistrationFailure::REASON_EMAIL_MISMATCH => 'field_email',
            SocialRegistrationFailure::REASON_INPUT_INVALID => 'field_validation',
            SocialRegistrationFailure::REASON_IDV_FAILED => 'idv_start',
            SocialRegistrationFailure::REASON_HOOK_FAILED => 'before_register',
            SocialRegistrationFailure::REASON_AUTO_LINK_NOT_ALLOWED => 'account_conflict',
            SocialRegistrationFailure::REASON_TOTP_PENDING_INVALID => 'totp_pending',
            SocialRegistrationFailure::REASON_TOTP_ENROLLMENT_INVALID => 'totp_verify',
            SocialRegistrationFailure::REASON_TOTP_ENROLLMENT_FAILED => 'totp_enrollment_internal',
            SocialRegistrationFailure::REASON_TOTP_PROVISION_CONFLICT => 'totp_provision_conflict',
            SocialRegistrationFailure::REASON_TOTP_PROVISION_FAILED => 'totp_provision_internal',
            default => 'submit_internal',
        };
    }

    private function registrationFailureStatus(string $reason): int
    {
        return in_array($reason, [
            SocialRegistrationFailure::REASON_PENDING_MISSING_OR_EXPIRED,
            SocialRegistrationFailure::REASON_PENDING_BINDING_MISMATCH,
            SocialRegistrationFailure::REASON_EMAIL_MISMATCH,
            SocialRegistrationFailure::REASON_INPUT_INVALID,
            SocialRegistrationFailure::REASON_AUTO_LINK_NOT_ALLOWED,
            SocialRegistrationFailure::REASON_TOTP_PENDING_INVALID,
            SocialRegistrationFailure::REASON_TOTP_ENROLLMENT_INVALID,
            SocialRegistrationFailure::REASON_TOTP_PROVISION_CONFLICT,
        ], true) ? 422 : 500;
    }

    public function beginRegistrationTotp(Request $request): JsonResponse
    {
        if (! $this->registration) {
            return $this->totpNoStore(response()->json(['message' => __('glitter-social_totp_passkey::messages.registration_failed')], 422));
        }

        $validated = $request->validate([
            'pending_id' => ['required', 'string', 'size:48'],
        ]);
        $binding = $this->resolveExchangeBinding($request);
        if ($binding === null) {
            return $this->totpNoStore(response()->json(['message' => __('glitter-social_totp_passkey::messages.registration_failed')], 422));
        }

        try {
            $result = $this->registration->beginTotpEnrollment(
                $validated['pending_id'],
                $binding,
                $request->session()->getId(),
                (string) $request->userAgent(),
            );
        } catch (\Throwable $e) {
            Log::channel('glitter_social_totp_passkey')->warning('glitter-social_totp_passkey: Social signup TOTP enrollment start failed', [
                'exception' => get_class($e),
                'action' => 'registration_totp_start',
            ]);

            return $this->totpNoStore(response()->json(['message' => __('glitter-social_totp_passkey::messages.registration_failed')], 422));
        }

        return $this->totpNoStore(response()->json($result));
    }

    public function completeRegistrationTotp(Request $request): JsonResponse
    {
        if (! $this->registration) {
            return $this->totpNoStore(response()->json(['message' => __('glitter-social_totp_passkey::messages.registration_failed')], 422));
        }

        $validated = $request->validate([
            'pending_id' => ['required', 'string', 'size:48'],
            'enrollment_id' => ['required', 'string', 'size:48'],
            'code' => ['required', 'digits:6'],
        ]);
        $binding = $this->resolveExchangeBinding($request);
        if ($binding === null) {
            return $this->totpNoStore(response()->json(['message' => __('glitter-social_totp_passkey::messages.registration_failed')], 422));
        }

        try {
            $result = $this->registration->completeTotpEnrollment(
                $validated['pending_id'],
                $binding,
                $request->session()->getId(),
                (string) $request->userAgent(),
                $validated['enrollment_id'],
                $validated['code'],
            );
        } catch (\Throwable $e) {
            Log::channel('glitter_social_totp_passkey')->warning('glitter-social_totp_passkey: Social signup TOTP enrollment failed', [
                'action' => 'registration_totp_confirm',
                'stage' => $this->registrationFailureStage(
                    $e instanceof SocialRegistrationFailure ? $e->reason : SocialRegistrationFailure::REASON_UNKNOWN,
                ),
                'reason' => $e instanceof SocialRegistrationFailure
                    ? $e->reason
                    : SocialRegistrationFailure::REASON_UNKNOWN,
                'exception' => get_class($e),
            ]);
            $reason = $e instanceof SocialRegistrationFailure
                ? $e->reason
                : SocialRegistrationFailure::REASON_UNKNOWN;

            return $this->totpNoStore(response()->json(
                ['message' => __('glitter-social_totp_passkey::messages.registration_failed')],
                $this->registrationFailureStatus($reason),
            ));
        }

        return $this->totpNoStore($this->registrationResult($result, $binding));
    }

    private function registrationResult(array $result, string $binding): JsonResponse
    {
        $user = $result['user'] ?? null;
        if (! $user instanceof User) {
            return response()->json(['message' => __('glitter-social_totp_passkey::messages.registration_failed')], 422);
        }

        if (($result['pending_verification'] ?? false) === true) {
            return response()->json([
                'redirect_url' => '/login?glitter_social_totp_passkey_error=registration_pending',
            ]);
        }

        if ($this->service->requiresAdditionalAuthentication($user)) {
            if (! $this->twoFactor) {
                return response()->json(['message' => __('glitter-social_totp_passkey::messages.registration_failed')], 422);
            }

            try {
                $pending = $this->twoFactor->start(
                    $user,
                    (string) ($result['provider'] ?? ''),
                    (string) ($result['provider_user_id'] ?? ''),
                    $binding,
                    (string) ($result['redirect_path'] ?? '/'),
                );

                return response()->json([
                    'redirect_url' => '/login?'.http_build_query(['glitter_social_totp_passkey_two_factor' => $pending['pending_id']]),
                ]);
            } catch (\Throwable) {
                return response()->json(['message' => __('glitter-social_totp_passkey::messages.registration_failed')], 422);
            }
        }

        // A registration result must also enter plugin-owned 2FA. A plain
        // exchange here would bypass that requirement.
        return response()->json(['message' => __('glitter-social_totp_passkey::messages.registration_failed')], 422);
    }

    public function accounts(Request $request): JsonResponse
    {
        $linked = SocialAccount::where('user_id', $request->user()->id)
            ->pluck('provider')
            ->all();

        return response()->json([
            'data' => [
                'linked_providers' => $linked,
                'totp_enabled' => $this->totp?->isEnabled($request->user()) ?? false,
            ],
        ]);
    }

    public function linkPrepare(Request $request, string $provider): JsonResponse
    {
        if (! $this->service->isEnabled($provider)) {
            return response()->json(['message' => __('common.not_found')], 404);
        }

        $nonce = $this->service->createLinkNonce($request->user(), $provider);

        // nonce 는 URL 이 아니라 세션에 싣는다. 이 라우트는 auth:sanctum 을 통과한 요청만
        // 닿을 수 있으므로, 연동 대상 회원을 정하는 값은 본인 브라우저의 세션에만 남는다.
        $request->session()->put(self::SESSION_LINK_NONCE, $nonce);

        return response()->json([
            'data' => [
                'redirect_url' => '/api/plugins/'.SocialAuthService::IDENTIFIER."/{$provider}/redirect",
            ],
        ]);
    }

    public function unlink(Request $request, string $provider): JsonResponse
    {
        $user = $request->user();

        $result = $this->service->unlinkAccount($user, $provider);

        if ($result === SocialLinkingService::UNLINK_BLOCKED) {
            return response()->json(['message' => __('glitter-social_totp_passkey::messages.profile.unlink_blocked_no_password')], 422);
        }

        return response()->json(['message' => __('glitter-social_totp_passkey::messages.profile.unlink_success')]);
    }

    private function frontendLoginError(string $key): RedirectResponse
    {
        return redirect('/login?'.http_build_query(['glitter_social_totp_passkey_error' => $key]));
    }

    private function frontendProfileError(string $key): RedirectResponse
    {
        return redirect('/mypage/profile?'.http_build_query(['glitter_social_totp_passkey_link' => 'error', 'glitter_social_totp_passkey_error' => $key]));
    }

    private function totpReauthenticationRequired(): JsonResponse
    {
        return $this->totpNoStore(response()
            ->json(['message' => __('glitter-social_totp_passkey::messages.totp.reauthentication_required')], 403)
        );
    }

    private function totpNoStore(JsonResponse $response): JsonResponse
    {
        return $response->withHeaders([
                'Cache-Control' => 'no-store, no-cache, max-age=0',
                'Pragma' => 'no-cache',
            ]);
    }

    private function resolveExchangeBinding(Request $request): ?string
    {
        $sessionBinding = $request->session()->get(self::SESSION_EXCHANGE_BINDING);
        $cookieBinding = $request->cookie(self::COOKIE_EXCHANGE_BINDING);

        if (is_string($sessionBinding) && $sessionBinding !== '') {
            if (is_string($cookieBinding)
                && $cookieBinding !== ''
                && ! hash_equals($sessionBinding, $cookieBinding)) {
                return null;
            }

            return $sessionBinding;
        }

        return is_string($cookieBinding) && $cookieBinding !== ''
            ? $cookieBinding
            : null;
    }

    private function exchangeBindingCookie(string $binding): Cookie
    {
        return cookie(
            self::COOKIE_EXCHANGE_BINDING,
            $binding,
            10,
            config('session.path', '/'),
            config('session.domain'),
            config('session.secure'),
            true,
            false,
            config('session.same_site', 'lax'),
        );
    }
}
