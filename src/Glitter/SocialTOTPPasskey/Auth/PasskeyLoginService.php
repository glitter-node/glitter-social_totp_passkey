<?php

namespace Glitter\SocialTOTPPasskey\Auth;

use App\ActivityLog\Traits\ResolvesActivityLogType;
use App\Auth\DTO\PasswordChangeRequirement;
use App\Contracts\Repositories\UserRepositoryInterface;
use App\Enums\ActivityLogType;
use App\Enums\UserStatus;
use App\Extension\HookManager;
use App\Http\Resources\UserResource;
use App\Models\User;
use App\Services\AuthService;
use App\Services\PasswordChangeChallengeService;
use App\Services\PasswordExpiryService;
use Glitter\SocialTOTPPasskey\Models\PasskeyCredential;
use Glitter\SocialTOTPPasskey\Passkey\PasskeyService;
use Glitter\SocialTOTPPasskey\Passkey\VerifiedPasskeyAuthentication;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Laravel\Sanctum\Sanctum;

final class PasskeyLoginService
{
    use ResolvesActivityLogType;

    public function __construct(
        private readonly PasskeyService $passkeys,
        private readonly SocialTotpService $totp,
        private readonly PasskeyLoginPendingStore $pending,
        private readonly UserRepositoryInterface $users,
        private readonly PasswordExpiryService $passwordExpiry,
        private readonly PasswordChangeChallengeService $passwordChallenges,
        private readonly AuthService $authService,
    ) {}

    public function continueLogin(
        VerifiedPasskeyAuthentication $authentication,
        string $sessionId,
        string $userAgent,
    ): PasskeyLoginResult {
        $user = $this->validatedUser($authentication, $sessionId, $userAgent);

        if ($this->loginRequiresTotp()) {
            try {
                $enabled = $this->totp->isEnabled($user);
            } catch (\Throwable $exception) {
                throw PasskeyLoginException::for('passkey_login_temporarily_unavailable', $exception);
            }

            if (! $enabled) {
                throw PasskeyLoginException::for('passkey_totp_enrollment_required');
            }

            $pending = $this->pending->create($authentication, $sessionId, $userAgent);

            return PasskeyLoginResult::totpRequired(
                $pending['pending_id'],
                $authentication->expiresAt(),
            );
        }

        return $this->completeLogin($authentication);
    }

    public function continueAfterTotp(
        string $pendingId,
        string $code,
        string $sessionId,
        string $userAgent,
    ): PasskeyLoginResult {
        $authentication = $this->pending->verifyAndClaim(
            $pendingId,
            $code,
            $sessionId,
            $userAgent,
        );

        $this->validatedUser($authentication, $sessionId, $userAgent);

        return $this->completeLogin($authentication);
    }

    private function completeLogin(VerifiedPasskeyAuthentication $authentication): PasskeyLoginResult
    {
        $connection = $this->assertConnectionParity();

        try {
            /** @var array{user: User, requirement: PasswordChangeRequirement|null, token: string|null} $outcome */
            $outcome = DB::connection($connection)->transaction(function () use ($authentication, $connection): array {
                $userId = $authentication->userId();
                if ($userId === null) {
                    throw PasskeyLoginException::for('passkey_verification_failed');
                }

                $user = User::on($connection)->whereKey($userId)->lockForUpdate()->first();
                if (! $user) {
                    throw PasskeyLoginException::for('passkey_login_unavailable');
                }

                $this->assertAccountMayLogin($user);
                $requirement = $this->passwordExpiry->loginRequirement($user);

                try {
                    $authentication->consume($user);
                } catch (\Throwable $exception) {
                    throw PasskeyLoginException::for('passkey_login_stale', $exception);
                }

                if ($requirement !== null) {
                    return ['user' => $user, 'requirement' => $requirement, 'token' => null];
                }

                $this->restoreDormantAccount($user);

                $lifetime = (int) g7_core_settings('security.auth_token_lifetime', 30);
                $expiresAt = $lifetime === 0 ? null : now()->addMinutes($lifetime);
                $token = $user->createToken('auth-token', ['*'], $expiresAt)->plainTextToken;

                return ['user' => $user, 'requirement' => null, 'token' => $token];
            });
        } catch (PasskeyLoginException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable', $exception);
        }

        if ($outcome['requirement'] !== null) {
            return $this->issuePasswordChangeChallenge($outcome['user'], $outcome['requirement']);
        }

        $token = $outcome['token'];
        if (! is_string($token) || $token === '') {
            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable');
        }

        return $this->completePostCommit($outcome['user'], $token);
    }

    private function validatedUser(
        VerifiedPasskeyAuthentication $authentication,
        string $sessionId,
        string $userAgent,
    ): User {
        $now = now()->getTimestamp();
        $userId = $authentication->userId();

        if (! $this->passkeyLoginEnabled()
            || $authentication->purpose() !== 'login'
            || ! $authentication->isUserVerified()
            || $userId === null
            || $userId < 1
            || $authentication->credentialId() < 1
            || strlen($authentication->transaction()) !== 64
            || $authentication->verifiedAt()->getTimestamp() < 1
            || $authentication->verifiedAt()->getTimestamp() > $now
            || $authentication->verifiedAt()->getTimestamp() > $authentication->expiresAt()->getTimestamp()
            || $authentication->expiresAt()->getTimestamp() <= $now
            || $sessionId === ''
            || $userAgent === ''
        ) {
            throw PasskeyLoginException::for('passkey_verification_failed');
        }

        try {
            $user = $this->users->findById($userId);
            $evidenceExists = PasskeyCredential::query()
                ->whereKey($authentication->credentialId())
                ->where('user_id', $userId)
                ->where('authentication_transaction_hash', hash('sha256', $authentication->transaction()))
                ->where('authentication_purpose', 'login')
                ->whereNull('authentication_consumed_at')
                ->where('authentication_expires_at', '>=', now())
                ->exists();
        } catch (\Throwable $exception) {
            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable', $exception);
        }

        if (! $user || ! $evidenceExists) {
            throw PasskeyLoginException::for('passkey_login_stale');
        }

        $this->assertAccountMayLogin($user);

        return $user;
    }

    private function assertAccountMayLogin(User $user): void
    {
        if (! in_array($user->status, [UserStatus::Active->value, UserStatus::Dormant->value], true)) {
            throw PasskeyLoginException::for('passkey_login_unavailable');
        }

        try {
            $locked = (bool) g7_core_settings('security.login_attempt_enabled', true)
                && $this->users->isLocked($user);
        } catch (\Throwable $exception) {
            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable', $exception);
        }

        if ($locked) {
            throw PasskeyLoginException::for('passkey_account_locked');
        }
    }

    private function issuePasswordChangeChallenge(
        User $user,
        PasswordChangeRequirement $requirement,
    ): PasskeyLoginResult {
        try {
            $challengeId = $this->passwordChallenges->issue($user, 'user', $requirement);
        } catch (\Throwable $exception) {
            throw PasskeyLoginException::for('passkey_password_change_unavailable', $exception);
        }

        if (! is_string($challengeId) || $challengeId === '') {
            throw PasskeyLoginException::for('passkey_password_change_unavailable');
        }

        return PasskeyLoginResult::passwordChangeRequired(
            $challengeId,
            $requirement->reason->value,
            $requirement->canPostpone,
            $requirement->postponeDays,
            $requirement->expiredAt?->toIso8601String(),
            now()->addSeconds(PasswordChangeChallengeService::TTL_SECONDS)->toIso8601String(),
        );
    }

    private function completePostCommit(User $user, string $token): PasskeyLoginResult
    {
        $stage = 'web_session';

        try {
            if (request()->hasSession() && request()->session()->isStarted()) {
                Auth::guard('web')->login($user);
            }

            $stage = 'after_login';
            HookManager::doAction('core.auth.after_login', $user, [
                'email' => (string) $user->email,
                'login_time' => now(),
                'ip_address' => request()->ip(),
                'user_agent' => request()->userAgent(),
            ]);

            $stage = 'user_serialization';
            $user->load(['roles.permissions']);
            $userData = (new UserResource($user))->toAuthArray(request());
            if (! is_array($userData)
                || ! is_string($userData['uuid'] ?? null)
                || $userData['uuid'] === ''
            ) {
                throw new \UnexpectedValueException('Authenticated user data is incomplete.');
            }

            $stage = 'authenticated_result';
            return PasskeyLoginResult::authenticated($userData, $token, '/');
        } catch (\Throwable $exception) {
            $this->compensatePostCommitFailure($user, $token, $exception, $stage);
        }
    }

    public function compensateAuthenticatedResponseFailure(
        string $token,
        \Throwable $failure,
    ): never {
        $this->compensatePostCommitFailure(
            $this->resolveIssuedTokenUser($token),
            $token,
            $failure,
            'http_response',
        );
    }

    private function compensatePostCommitFailure(
        ?User $user,
        string $token,
        \Throwable $failure,
        string $stage,
    ): never {
        $revokeFailed = false;

        try {
            if (! $user) {
                throw new \RuntimeException('Issued passkey login user is unavailable.');
            }

            $this->authService->revokeIssuedSession($user, $token);
        } catch (\Throwable) {
            $revokeFailed = true;
        }

        try {
            if (request()->hasSession() && request()->session()->isStarted() && Auth::guard('web')->check()) {
                Auth::guard('web')->logout();
            }
        } catch (\Throwable) {
            // Best effort only; the plaintext token is never returned.
        }

        try {
            Log::critical('Passkey login post-commit processing failed.', [
                'stage' => $stage,
                'failure_type' => $failure::class,
                'token_revoke_failed' => $revokeFailed,
            ]);
        } catch (\Throwable) {
            // Logging failure must not expose or return the issued token.
        }

        throw PasskeyLoginException::for('passkey_login_temporarily_unavailable', $failure);
    }

    private function resolveIssuedTokenUser(string $token): ?User
    {
        try {
            $tokenModel = Sanctum::$personalAccessTokenModel;
            if (! is_string($tokenModel) || ! is_a($tokenModel, Model::class, true)) {
                return null;
            }

            $accessToken = $tokenModel::findToken($token);
            $tokenable = $accessToken?->tokenable;

            return $tokenable instanceof User ? $tokenable : null;
        } catch (\Throwable) {
            return null;
        }
    }

    private function restoreDormantAccount(User $user): bool
    {
        if ($user->status !== UserStatus::Dormant->value) {
            if ($user->dormant_notified_at !== null
                && ! $this->users->update($user, ['dormant_notified_at' => null])
            ) {
                throw PasskeyLoginException::for('passkey_login_temporarily_unavailable');
            }

            return false;
        }

        if (! $this->users->update($user, array_merge(
            ['status' => UserStatus::Active->value],
            UserStatus::Active->transitionTimestamps(),
        ))) {
            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable');
        }

        $this->logActivity('user.dormant_restored', [
            'log_type' => ActivityLogType::User,
            'description_key' => 'activity_log.description.user_dormant_restored',
            'description_params' => ['user_id' => (string) $user->uuid],
            'user_id' => $user->id,
            'properties' => [
                'user_uuid' => (string) $user->uuid,
                'restored_by' => 'login',
            ],
        ]);

        return true;
    }

    private function assertConnectionParity(): string
    {
        try {
            $default = (string) config('database.default');
            $userConnection = $this->connectionName(new User, $default);
            $credentialConnection = $this->connectionName(new PasskeyCredential, $default);
            $tokenModel = Sanctum::$personalAccessTokenModel;

            if (! is_string($tokenModel) || ! is_a($tokenModel, Model::class, true)) {
                throw PasskeyLoginException::for('passkey_login_temporarily_unavailable');
            }

            /** @var Model $token */
            $token = new $tokenModel;
            $tokenConnection = $this->connectionName($token, $default);
        } catch (PasskeyLoginException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable', $exception);
        }

        if ($default === ''
            || $userConnection !== $credentialConnection
            || $userConnection !== $tokenConnection
        ) {
            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable');
        }

        return $userConnection;
    }

    private function connectionName(Model $model, string $default): string
    {
        $connection = $model->getConnectionName();

        return is_string($connection) && $connection !== '' ? $connection : $default;
    }

    private function passkeyLoginEnabled(): bool
    {
        try {
            return $this->passkeys->loginEnabled();
        } catch (\Throwable $exception) {
            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable', $exception);
        }
    }

    private function loginRequiresTotp(): bool
    {
        try {
            return $this->passkeys->loginRequiresTotp();
        } catch (\Throwable $exception) {
            throw PasskeyLoginException::for('passkey_login_temporarily_unavailable', $exception);
        }
    }
}
