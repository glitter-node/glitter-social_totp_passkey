<?php

namespace Glitter\SocialTOTPPasskey\Http\Controllers;

use App\Http\Controllers\Controller;
use Glitter\SocialTOTPPasskey\Auth\PasskeyLoginException;
use Glitter\SocialTOTPPasskey\Auth\PasskeyLoginResult;
use Glitter\SocialTOTPPasskey\Auth\PasskeyLoginService;
use Glitter\SocialTOTPPasskey\Auth\SocialTwoFactorService;
use Glitter\SocialTOTPPasskey\Passkey\PasskeyAuthenticationResult;
use Glitter\SocialTOTPPasskey\Passkey\PasskeyManagementException;
use Glitter\SocialTOTPPasskey\Passkey\PasskeyService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;

final class PasskeyController extends Controller
{
    private const SESSION_EXCHANGE_BINDING = 'glitter_social_totp_passkey.exchange_binding';

    private const COOKIE_EXCHANGE_BINDING = 'glitter_social_totp_passkey_exchange_binding';

    public function __construct(
        private readonly PasskeyService $passkeys,
        private readonly SocialTwoFactorService $twoFactor,
        private readonly PasskeyLoginService $login,
    ) {}

    public function registerOptions(Request $request): JsonResponse
    {
        $validated = $request->validate(['reauth_token' => ['required', 'string', 'size:64']]);

        return $this->attempt(fn () => $this->passkeys->beginRegistration(
            $request->user(), $validated['reauth_token'], $request->session()->getId(), (string) $request->userAgent(),
        ));
    }

    public function registerVerify(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'challenge_id' => ['required', 'string', 'size:48'],
            'credential' => ['required', 'array'],
            'name' => ['nullable', 'string', 'max:100'],
            'reauth_token' => ['required', 'string', 'size:64'],
        ]);

        return $this->attempt(function () use ($request, $validated): array {
            $credential = $this->passkeys->finishRegistration(
                $request->user(), $validated['challenge_id'], $validated['credential'],
                (string) ($validated['name'] ?? 'Passkey'), $validated['reauth_token'],
                $request->session()->getId(), (string) $request->userAgent(),
            );

            return ['id' => $credential->getKey(), 'name' => $credential->name];
        });
    }

    public function authenticateOptions(Request $request): JsonResponse
    {
        try {
            $validated = $request->validate([
                'purpose' => ['nullable', 'string', 'in:login,social'],
                'pending_id' => ['nullable', 'string', 'max:128'],
            ]);
        } catch (ValidationException $exception) {
            return $this->validationFailure($exception);
        }
        $purpose = (string) ($validated['purpose'] ?? 'login');
        $expectedUser = null;
        $context = null;

        if ($purpose === 'social') {
            $binding = $this->resolveExchangeBinding($request);
            $pendingId = (string) ($validated['pending_id'] ?? '');
            $expectedUser = $binding === null ? null : $this->twoFactor->resolvePasskeyUser($pendingId, $binding);
            if (! $expectedUser) {
                return $this->failure();
            }
            $context = $pendingId."\0".$binding;
        }

        $response = $this->attempt(fn () => $this->passkeys->beginAuthentication(
            $purpose, $request->session()->getId(), (string) $request->userAgent(), $expectedUser, $context,
        ));

        return $purpose === 'login' ? $this->noStore($response) : $response;
    }

    public function authenticateVerify(Request $request): JsonResponse
    {
        try {
            $validated = $request->validate([
                'purpose' => ['nullable', 'string', 'in:login,social'],
                'pending_id' => ['nullable', 'string', 'max:128'],
                'challenge_id' => ['required', 'string', 'size:48'],
                'credential' => ['required', 'array'],
            ]);
        } catch (ValidationException $exception) {
            return $this->validationFailure($exception);
        }
        $purpose = (string) ($validated['purpose'] ?? 'login');
        $binding = $purpose === 'social' ? $this->resolveExchangeBinding($request) : null;
        $context = $purpose === 'social' && $binding !== null
            ? (string) ($validated['pending_id'] ?? '')."\0".$binding
            : null;

        try {
            $result = $this->passkeys->finishAuthentication(
                $purpose, $validated['challenge_id'], $validated['credential'],
                $request->session()->getId(), (string) $request->userAgent(), $context,
            );
        } catch (\Throwable $exception) {
            $this->logFailure($purpose, $exception);

            return $purpose === 'login'
                ? $this->loginFailure(PasskeyLoginException::for('passkey_verification_failed', $exception))
                : $this->failure();
        }

        try {
            return match ($purpose) {
                'social' => $this->finishSocial($result, (string) ($validated['pending_id'] ?? ''), $binding),
                default => $this->finishLogin($request, $result),
            };
        } catch (PasskeyLoginException $exception) {
            $this->logFailure($purpose, $exception);

            return $this->loginFailure($exception);
        } catch (\Throwable $exception) {
            $this->logFailure($purpose, $exception);

            return $purpose === 'login'
                ? $this->unexpectedLoginFailure()
                : $this->failure();
        }
    }

    public function reauthenticateOptions(Request $request): JsonResponse
    {
        try {
            return response()->json($this->passkeys->beginAuthentication(
                'reauth', $request->session()->getId(), (string) $request->userAgent(), $request->user(),
            ));
        } catch (\RuntimeException $exception) {
            if ($exception->getMessage() === PasskeyService::ERROR_REAUTHENTICATION_CREDENTIAL_MISSING) {
                return $this->failure(409, 'glitter-social_totp_passkey::messages.passkey.credential_missing');
            }

            $this->logFailure('management', $exception);

            return $this->failure();
        } catch (\Throwable $exception) {
            $this->logFailure('management', $exception);

            return $this->failure();
        }
    }

    public function reauthenticateVerify(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'challenge_id' => ['required', 'string', 'size:48'],
            'credential' => ['required', 'array'],
        ]);

        try {
            $result = $this->passkeys->finishAuthentication(
                'reauth', $validated['challenge_id'], $validated['credential'],
                $request->session()->getId(), (string) $request->userAgent(),
            );

            return $this->finishReauthentication($request, $result);
        } catch (\Throwable $exception) {
            $this->logFailure('reauth', $exception);

            return $this->failure();
        }
    }

    public function completeLoginTotp(Request $request): JsonResponse
    {
        try {
            $validated = $request->validate([
                'pending_id' => ['required', 'string', 'size:48'],
                'code' => ['required', 'digits:6'],
            ]);
        } catch (ValidationException $exception) {
            return $this->validationFailure($exception);
        }

        try {
            $result = $this->login->continueAfterTotp(
                $validated['pending_id'],
                $validated['code'],
                $request->session()->getId(),
                (string) $request->userAgent(),
            );

            return $this->loginResult($request, $result);
        } catch (PasskeyLoginException $exception) {
            $this->logFailure('login_totp', $exception);

            return $this->loginFailure($exception);
        } catch (\Throwable $exception) {
            $this->logFailure('login_totp', $exception);

            return $this->unexpectedLoginFailure();
        }
    }

    public function credentials(Request $request): JsonResponse
    {
        return response()->json(['data' => $this->passkeys->credentials($request->user())]);
    }

    public function rename(Request $request, int $id): JsonResponse
    {
        $validated = $request->validate(['name' => ['required', 'string', 'max:100']]);

        return $this->attempt(function () use ($request, $validated, $id): array {
            $credential = $this->passkeys->rename($request->user(), $id, $validated['name']);

            return ['id' => $credential->getKey(), 'name' => $credential->name];
        });
    }

    public function delete(Request $request, int $id): JsonResponse
    {
        $validated = $request->validate(['reauth_token' => ['required', 'string', 'size:64']]);

        try {
            $this->passkeys->delete(
                $request->user(), $id, $validated['reauth_token'],
                $request->session()->getId(), (string) $request->userAgent(),
            );

            return response()->json(['deleted' => true]);
        } catch (PasskeyManagementException $exception) {
            $this->logFailure('management_delete', $exception);

            return $this->managementFailure($exception);
        } catch (\Throwable $exception) {
            $this->logFailure('management_delete', $exception);

            return $this->managementFailure(PasskeyManagementException::for(
                'passkey_management_unavailable',
                $exception,
            ));
        }
    }

    private function finishLogin(Request $request, PasskeyAuthenticationResult $result): JsonResponse
    {
        if (! $result->evidence || ! $result->evidence->isUserVerified()) {
            throw PasskeyLoginException::for('passkey_verification_failed');
        }

        $loginResult = $this->login->continueLogin(
            $result->evidence,
            $request->session()->getId(),
            (string) $request->userAgent(),
        );

        return $this->loginResult($request, $loginResult);
    }

    private function finishSocial(PasskeyAuthenticationResult $result, string $pendingId, ?string $binding): JsonResponse
    {
        if ($binding === null) {
            return $this->failure();
        }
        $code = $this->twoFactor->completeWithPasskey(
            $pendingId, $binding, $result->user, $result->challengeReference,
        );

        return $code === null
            ? $this->failure()
            : response()->json(['redirect_url' => '/login?'.http_build_query(['glitter_social_totp_passkey_exchange' => $code])]);
    }

    private function finishReauthentication(Request $request, PasskeyAuthenticationResult $result): JsonResponse
    {
        if (! $request->user() || (int) $request->user()->getKey() !== (int) $result->user->getKey()) {
            return $this->failure(403);
        }

        return response()->json(['reauth_token' => $this->passkeys->issueReauthentication(
            $result->user, $request->session()->getId(), (string) $request->userAgent(),
        )]);
    }

    private function loginResult(Request $request, PasskeyLoginResult $result): JsonResponse
    {
        $data = $result->data();

        $response = match ($result->state()) {
            PasskeyLoginResult::TOTP_REQUIRED => $this->totpRequiredResponse($data),
            PasskeyLoginResult::PASSWORD_CHANGE_REQUIRED => $this->passwordChangeRequiredResponse($data),
            PasskeyLoginResult::AUTHENTICATED => $this->authenticatedResponse($request, $data),
            default => $this->unexpectedLoginFailure(),
        };

        return $this->noStore($response);
    }

    /** @param array<string, mixed> $data */
    private function totpRequiredResponse(array $data): JsonResponse
    {
        if (! is_string($data['pending_id'] ?? null)
            || $data['pending_id'] === ''
            || ! is_string($data['expires_at'] ?? null)
            || $data['expires_at'] === ''
        ) {
            return $this->unexpectedLoginFailure();
        }

        return response()->json([
            'totp_required' => true,
            'pending_id' => $data['pending_id'],
            'expires_at' => $data['expires_at'],
        ]);
    }

    /** @param array<string, mixed> $data */
    private function passwordChangeRequiredResponse(array $data): JsonResponse
    {
        if (! is_string($data['challenge_id'] ?? null)
            || $data['challenge_id'] === ''
            || ! is_string($data['reason'] ?? null)
            || $data['reason'] === ''
            || ! is_bool($data['can_postpone'] ?? null)
            || ! is_string($data['expires_at'] ?? null)
            || $data['expires_at'] === ''
        ) {
            return $this->unexpectedLoginFailure();
        }

        return response()->json([
            'password_change_required' => true,
            'challenge_id' => $data['challenge_id'],
            'reason' => $data['reason'],
            'can_postpone' => $data['can_postpone'],
            'postpone_days' => is_int($data['postpone_days'] ?? null) ? $data['postpone_days'] : null,
            'expired_at' => is_string($data['expired_at'] ?? null) ? $data['expired_at'] : null,
            'expires_at' => $data['expires_at'],
        ]);
    }

    /** @param array<string, mixed> $data */
    private function authenticatedResponse(Request $request, array $data): JsonResponse
    {
        $userData = $data['user'] ?? null;
        $token = $data['token'] ?? null;
        $redirectPath = $data['redirect_path'] ?? null;

        if (! is_array($userData)
            || ! is_string($userData['uuid'] ?? null)
            || $userData['uuid'] === ''
            || ! is_string($token)
            || $token === ''
            || ! is_string($redirectPath)
            || $redirectPath === ''
        ) {
            if (is_string($token) && $token !== '') {
                $this->login->compensateAuthenticatedResponseFailure(
                    $token,
                    new \UnexpectedValueException('Authenticated response data is incomplete.'),
                );
            }

            return $this->unexpectedLoginFailure();
        }

        try {
            $response = response()->json([
                'message' => __('auth.login_success'),
                'data' => $userData,
                'token' => $token,
                'redirect_path' => $redirectPath,
            ]);
        } catch (\Throwable $exception) {
            $this->login->compensateAuthenticatedResponseFailure($token, $exception);
        }

        return $response;
    }

    private function resolveExchangeBinding(Request $request): ?string
    {
        $session = $request->session()->get(self::SESSION_EXCHANGE_BINDING);
        $cookie = $request->cookie(self::COOKIE_EXCHANGE_BINDING);
        if (is_string($session) && $session !== '') {
            return is_string($cookie) && $cookie !== '' && ! hash_equals($session, $cookie) ? null : $session;
        }

        return is_string($cookie) && $cookie !== '' ? $cookie : null;
    }

    private function attempt(callable $callback): JsonResponse
    {
        try {
            return response()->json($callback());
        } catch (\Throwable $exception) {
            $this->logFailure('management', $exception);

            return $this->failure();
        }
    }

    private function loginFailure(PasskeyLoginException $exception): JsonResponse
    {
        return response()->json([
            'message' => __($exception->messageKey()),
            'error_code' => $exception->errorCode(),
        ], $exception->httpStatus())->header('Cache-Control', 'no-store');
    }

    private function unexpectedLoginFailure(): JsonResponse
    {
        return response()->json([
            'message' => __('glitter-social_totp_passkey::messages.passkey.failed'),
            'error_code' => 'passkey_login_temporarily_unavailable',
        ], 503)->header('Cache-Control', 'no-store');
    }

    private function managementFailure(PasskeyManagementException $exception): JsonResponse
    {
        return response()->json([
            'message' => __('glitter-social_totp_passkey::messages.passkey.failed'),
            'error_code' => $exception->errorCode(),
        ], $exception->httpStatus())->header('Cache-Control', 'no-store');
    }

    private function validationFailure(ValidationException $exception): JsonResponse
    {
        return response()->json([
            'message' => $exception->getMessage(),
            'errors' => $exception->errors(),
        ], $exception->status)->header('Cache-Control', 'no-store');
    }

    private function noStore(JsonResponse $response): JsonResponse
    {
        return $response->header('Cache-Control', 'no-store');
    }

    private function failure(int $status = 422, ?string $messageKey = null): JsonResponse
    {
        return response()->json(['message' => __($messageKey ?? 'glitter-social_totp_passkey::messages.passkey.failed')], $status)
            ->header('Cache-Control', 'no-store');
    }

    private function logFailure(string $purpose, \Throwable $exception): void
    {
        Log::channel('glitter_social_totp_passkey')->notice('glitter-social_totp_passkey: passkey operation rejected', [
            'action' => 'passkey', 'stage' => $purpose, 'exception' => get_class($exception),
        ]);
    }
}
