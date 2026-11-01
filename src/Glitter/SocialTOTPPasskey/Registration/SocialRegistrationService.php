<?php

namespace Glitter\SocialTOTPPasskey\Registration;

use App\Contracts\Repositories\RoleRepositoryInterface;
use App\Contracts\Repositories\UserConsentRepositoryInterface;
use App\Enums\ConsentType;
use App\Enums\IdentityVerificationPurpose;
use App\Enums\IdentityVerificationStatus;
use App\Enums\UserStatus;
use App\Extension\HookManager;
use App\Models\User;
use App\Services\IdentityPolicyService;
use App\Services\IdentityVerificationService;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Glitter\SocialTOTPPasskey\Auth\SocialLoginEligibility;
use Glitter\SocialTOTPPasskey\Auth\SocialTotpService;
use Glitter\SocialTOTPPasskey\Linking\SocialLinkingService;
use Glitter\SocialTOTPPasskey\Models\SocialLoginTotp;
use Glitter\SocialTOTPPasskey\Models\SocialLoginUserFlag;
use Glitter\SocialTOTPPasskey\Support\RedirectPath;

/**
 * OAuth identity가 아직 회원과 연결되지 않았을 때의 다단계 가입 흐름입니다.
 *
 * User는 동의·필수 입력·필요한 signup IDV가 끝날 때까지 생성하지 않습니다.
 * signup_after_create 정책이 활성화된 경우에는 challenge 결과를 pending
 * registration에 안전하게 결합할 public contract가 없으므로 User 생성을
 * fail closed 합니다.
 */
final class SocialRegistrationService
{
    private const PENDING_TTL_SECONDS = 600;

    private const LOCK_SECONDS = 10;

    private const CACHE_PREFIX = 'glitter_social_totp_passkey:registration:';

    public const ERROR_INVALID = 'glitter_social_totp_passkey_registration_invalid';

    public const ERROR_CONFLICT = 'glitter_social_totp_passkey_registration_conflict';

    public const ERROR_IDV_REQUIRED = 'glitter_social_totp_passkey_registration_idv_required';

    /**
     * @return array{registration_id: string}
     */
    public function createPending(
        string $provider,
        string $providerUserId,
        ?string $providerProfileEmail,
        ?string $registrationEmail,
        ?string $displayName,
        string $sessionBinding,
        string $redirectPath,
    ): array {
        if ($provider === '' || $providerUserId === '' || $sessionBinding === '') {
            throw new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_INPUT_INVALID);
        }

        $registrationId = Str::random(48);
        try {
            $stored = Cache::put($this->key($registrationId), [
                'provider' => $provider,
                'provider_user_id' => $providerUserId,
                'provider_profile_email' => $providerProfileEmail,
                'registration_email' => $registrationEmail,
                'display_name' => $displayName,
                'session_binding_hash' => hash('sha256', $sessionBinding),
                'redirect_path' => RedirectPath::sanitize($redirectPath),
                'state' => 'collecting',
                'fields' => null,
                'challenge_id' => null,
                'before_register_verified' => false,
            ], now()->addSeconds(self::PENDING_TTL_SECONDS));
        } catch (\Throwable $e) {
            throw new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_PENDING_WRITE_FAILED, $e);
        }

        if (! $stored) {
            throw new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_PENDING_WRITE_FAILED);
        }

        return ['registration_id' => $registrationId];
    }

    /**
     * 동의/필수 입력을 수집하고, 필요하면 signup IDV challenge를 발행합니다.
     *
     * @return array{status: string, challenge_id?: string, expires_at?: string, user?: User, pending_verification?: bool, redirect_path?: string}
     */
    public function submit(
        string $registrationId,
        string $sessionBinding,
        string $sessionId,
        string $userAgent,
        array $input,
    ): array {
        try {
            return $this->withPendingLock($registrationId, $sessionBinding, function (array $pending, string $key) use ($input, $registrationId, $sessionBinding, $sessionId, $userAgent): array {
                $fields = $this->normalizeFields($pending, $input);

                try {
                    $policy = $this->signupBeforePolicy();

                    if ($policy?->enabled) {
                        $challenge = $this->identityVerification->start(
                            IdentityVerificationPurpose::Signup->value,
                            ['email' => $fields['email']],
                            [
                                'origin_type' => 'route',
                                'origin_identifier' => 'glitter.social_totp_passkey.registration',
                                'origin_policy_key' => $policy->key,
                                'ip_address' => request()->ip(),
                                'user_agent' => request()->userAgent(),
                            ],
                            $policy->provider_id,
                        );

                        $status = $this->identityVerification->getStatus($challenge->id);
                        if ($status === null
                            || ($status['purpose'] ?? null) !== IdentityVerificationPurpose::Signup->value
                            || ! in_array($status['status'] ?? null, [
                                IdentityVerificationStatus::Requested->value,
                                IdentityVerificationStatus::Sent->value,
                                IdentityVerificationStatus::Processing->value,
                            ], true)
                        ) {
                            throw new \RuntimeException(self::ERROR_IDV_REQUIRED);
                        }

                        $pending['state'] = 'awaiting_idv';
                        $pending['fields'] = $fields;
                        $pending['challenge_id'] = $challenge->id;
                        $this->storePending($key, $pending, $challenge->expiresAt);

                        return [
                            'status' => 'idv_required',
                            'challenge_id' => $challenge->id,
                            'expires_at' => $challenge->expiresAt->toIso8601String(),
                        ];
                    }
                } catch (SocialRegistrationFailure $e) {
                    throw $e;
                } catch (\Throwable $e) {
                    throw new SocialRegistrationFailure(self::ERROR_IDV_REQUIRED, SocialRegistrationFailure::REASON_IDV_FAILED, $e);
                }

                return $this->prepareTotpPending($pending, $key, $fields);
            }, true);
        } catch (SocialRegistrationFailure $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_UNKNOWN, $e);
        }
    }

    /**
     * signup purpose IDV를 검증한 뒤 최종 provisioning을 수행합니다.
     * verification_token은 메모리 안에서 policy enforce/consume에만 사용하고 저장하지 않습니다.
     *
     * @return array{status: string, user?: User, pending_verification?: bool, redirect_path?: string}
     */
    public function completeIdentityVerification(
        string $registrationId,
        string $sessionBinding,
        string $sessionId,
        string $userAgent,
        string $code,
    ): array {
        return $this->withPendingLock($registrationId, $sessionBinding, function (array $pending, string $key) use ($code, $registrationId, $sessionBinding, $sessionId, $userAgent): array {
            if (($pending['state'] ?? null) !== 'awaiting_idv'
                || ! is_string($pending['challenge_id'] ?? null)
                || ! is_array($pending['fields'] ?? null)
            ) {
                throw new \RuntimeException(self::ERROR_INVALID);
            }

            $challengeId = $pending['challenge_id'];
            $status = $this->identityVerification->getStatus($challengeId);
            if ($status === null
                || ($status['purpose'] ?? null) !== IdentityVerificationPurpose::Signup->value
                || ! in_array($status['status'] ?? null, [
                    IdentityVerificationStatus::Requested->value,
                    IdentityVerificationStatus::Sent->value,
                    IdentityVerificationStatus::Processing->value,
                ], true)
            ) {
                throw new \RuntimeException(self::ERROR_INVALID);
            }

            $verification = $this->identityVerification->verify(
                $challengeId,
                ['code' => $code],
                [
                    'origin_type' => 'route',
                    'origin_identifier' => 'glitter.social_totp_passkey.registration',
                ],
            );

            if (! $verification->success) {
                throw new \RuntimeException(self::ERROR_INVALID);
            }

            $policy = $this->signupBeforePolicy();
            $verificationToken = $verification->claims['verification_token'] ?? null;
            if (! $policy?->enabled || ! is_string($verificationToken) || $verificationToken === '') {
                throw new \RuntimeException(self::ERROR_INVALID);
            }

            // Core와 같은 public policy service로 purpose/target을 재검증합니다.
            $this->identityPolicies->enforce($policy, null, [
                'signup_stage' => 'before_submit',
                'http_method' => 'POST',
                'target_email' => $pending['fields']['email'],
                'verification_token' => $verificationToken,
                'origin_type' => 'route',
                'origin_identifier' => 'glitter.social_totp_passkey.registration',
            ]);
            $this->dispatchBeforeRegister($pending['fields'], $verificationToken);
            $this->identityVerification->consumeToken($verificationToken);

            $pending['before_register_verified'] = true;

            return $this->prepareTotpPending(
                $pending,
                $key,
                $pending['fields'],
            );
        });
    }

    /**
     * TOTP secret은 아직 User가 없는 상태에서 짧게 발급하고, 별도 서버 cache에
     * 저장합니다. User 생성은 confirmTotpEnrollment 이후에만 수행됩니다.
     *
     * @return array{status: string, enrollment: array<string, string>, redirect_path: string}
     */
    public function beginTotpEnrollment(
        string $registrationId,
        string $sessionBinding,
        string $sessionId,
        string $userAgent,
    ): array {
        return $this->withPendingLock($registrationId, $sessionBinding, function (array $pending, string $key) use ($registrationId, $sessionBinding, $sessionId, $userAgent): array {
            if (($pending['state'] ?? null) !== 'awaiting_totp'
                || ! is_array($pending['fields'] ?? null)
                || ! is_string($pending['provider'] ?? null)
                || ! is_string($pending['provider_user_id'] ?? null)
            ) {
                throw new \RuntimeException(self::ERROR_INVALID);
            }

            $payload = $this->totp->beginRegistrationEnrollment(
                $registrationId,
                $pending['provider'],
                $pending['provider_user_id'],
                $sessionBinding,
                $sessionId,
                $userAgent,
                (string) ($pending['fields']['email'] ?? $pending['provider']),
            );

            $pending['totp_enrollment_id'] = $payload['enrollment_id'];
            $this->storePending($key, $pending, now()->addSeconds(self::PENDING_TTL_SECONDS));

            return [
                'status' => 'totp_required',
                'enrollment' => $payload,
                'redirect_path' => RedirectPath::sanitize($pending['redirect_path'] ?? '/'),
            ];
        });
    }

    /**
     * 올바른 TOTP를 확인한 뒤에만 User·SocialAccount·TOTP를 하나의 transaction으로
     * 생성합니다. 실패하면 pending과 임시 secret을 폐기합니다.
     *
     * @return array<string, mixed>
     */
    public function completeTotpEnrollment(
        string $registrationId,
        string $sessionBinding,
        string $sessionId,
        string $userAgent,
        string $enrollmentId,
        string $code,
    ): array {
        return $this->withPendingLock($registrationId, $sessionBinding, function (array $pending, string $key) use ($registrationId, $sessionBinding, $sessionId, $userAgent, $enrollmentId, $code): array {
            if (($pending['state'] ?? null) !== 'awaiting_totp'
                || ! is_array($pending['fields'] ?? null)
                || ! is_string($pending['provider'] ?? null)
                || ! is_string($pending['provider_user_id'] ?? null)
                || ! hash_equals((string) ($pending['totp_enrollment_id'] ?? ''), $enrollmentId)
            ) {
                throw new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_TOTP_PENDING_INVALID);
            }

            try {
                $result = $this->totp->confirmRegistrationEnrollment(
                    $registrationId,
                    $enrollmentId,
                    $pending['provider'],
                    $pending['provider_user_id'],
                    $sessionBinding,
                    $sessionId,
                    $userAgent,
                    $code,
                    function (string $encryptedSecret, int $counter) use ($pending): array {
                        try {
                            return $this->provision($pending, $pending['fields'], $encryptedSecret, $counter);
                        } catch (SocialRegistrationFailure $e) {
                            throw $e;
                        } catch (\RuntimeException $e) {
                            if ($e->getMessage() === self::ERROR_CONFLICT) {
                                throw new SocialRegistrationFailure(self::ERROR_CONFLICT, SocialRegistrationFailure::REASON_TOTP_PROVISION_CONFLICT, $e);
                            }

                            throw new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_TOTP_PROVISION_FAILED, $e);
                        } catch (\Throwable $e) {
                            throw new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_TOTP_PROVISION_FAILED, $e);
                        }
                    },
                );
            } catch (SocialRegistrationFailure $e) {
                throw $e;
            } catch (\Throwable $e) {
                throw new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_TOTP_ENROLLMENT_FAILED, $e);
            }

            if ($result === null) {
                throw new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_TOTP_ENROLLMENT_INVALID);
            }

            Cache::forget($key);

            return $result;
        }, true);
    }

    private function prepareTotpPending(
        array $pending,
        string $key,
        array $fields,
    ): array {
        $pending['state'] = 'awaiting_totp';
        $pending['fields'] = $fields;
        $pending['challenge_id'] = null;
        unset($pending['totp_enrollment_id']);
        try {
            $this->storePending($key, $pending, now()->addSeconds(self::PENDING_TTL_SECONDS));
        } catch (\Throwable $e) {
            throw new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_PENDING_WRITE_FAILED, $e);
        }

        return [
            'status' => 'totp_required',
            'redirect_path' => RedirectPath::sanitize($pending['redirect_path'] ?? '/'),
        ];
    }

    private function provision(array $pending, array $fields, string $encryptedSecret, int $counter): array
    {
        if ($encryptedSecret === '' || $counter < 0) {
            throw new \RuntimeException(self::ERROR_INVALID);
        }

        // TOTP 검증이 끝난 후에만 신규 Social User를 생성합니다.
        $this->eligibility->assertCanCreateSocialUser();

        $afterPolicy = $this->signupAfterPolicy();
        // Core after_register listener는 challenge를 발행하지만 challenge ID를 가입
        // 응답에 돌려주지 않습니다. plugin이 그 challenge를 browser-bound pending
        // registration과 안전하게 연결할 public contract가 없으므로 User를 만들지 않습니다.
        if ($afterPolicy?->enabled) {
            throw new \RuntimeException(self::ERROR_IDV_REQUIRED);
        }

        $status = UserStatus::Active->value;
        $now = now();

        if (($pending['before_register_verified'] ?? false) !== true) {
            try {
                $this->dispatchBeforeRegister($fields);
            } catch (\Throwable $e) {
                throw new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_HOOK_FAILED, $e);
            }
        }

        try {
            $result = DB::transaction(function () use ($pending, $fields, $status, $now, $encryptedSecret, $counter): array {
                $existingIdentity = $this->linking->findIdentityForUpdate(
                    $pending['provider'],
                    $pending['provider_user_id'],
                );
                if ($existingIdentity) {
                    throw new \RuntimeException(self::ERROR_CONFLICT);
                }

                $matchedUser = User::query()
                    ->where('email', $fields['email'])
                    ->lockForUpdate()
                    ->first();

                if ($matchedUser) {
                    throw new \RuntimeException(self::ERROR_CONFLICT);
                }

                $user = new User([
                    'name' => $fields['name'],
                    'nickname' => $fields['nickname'],
                    'email' => $fields['email'],
                    // DB의 password 컬럼은 채우되 SocialLoginUserFlag가 실제 password
                    // 보유 여부의 authoritative plugin state로 남습니다.
                    'password' => Hash::make(Str::random(40)),
                    'language' => $fields['language'],
                    'status' => $status,
                ]);
                $user->saveOrFail();

                $flag = new SocialLoginUserFlag([
                    'user_id' => $user->id,
                    'has_real_password' => false,
                ]);
                $flag->saveOrFail();

                $totp = new SocialLoginTotp([
                    'user_id' => $user->id,
                    'encrypted_secret' => $encryptedSecret,
                    'enabled_at' => now(),
                    'last_used_counter' => $counter,
                    'failed_attempts' => 0,
                    'locked_until' => null,
                ]);
                $totp->saveOrFail();

                $role = $this->roles->findByIdentifier('user');
                if ($role) {
                    $user->roles()->sync([$role->id]);
                }

                $this->linking->attachWithinTransaction(
                    $user,
                    $pending['provider'],
                    $pending['provider_user_id'],
                    $pending['provider_profile_email'] ?? $pending['provider_email'] ?? null,
                );

                foreach ([ConsentType::Terms->value, ConsentType::Privacy->value] as $type) {
                    $this->consents->record([
                        'user_id' => $user->id,
                        'consent_type' => $type,
                        'agreed_at' => $now,
                        'ip_address' => request()->ip(),
                    ]);
                }

                return [
                    'status' => 'provisioned',
                    'user' => $user,
                    'pending_verification' => false,
                    'redirect_path' => RedirectPath::sanitize($pending['redirect_path'] ?? null),
                    'registration_data' => [
                        'name' => $fields['name'],
                        'nickname' => $fields['nickname'],
                        'email' => $fields['email'],
                        'agree_terms' => true,
                        'agree_privacy' => true,
                        'language' => $fields['language'],
                    ],
                ];
            });
        } catch (QueryException $e) {
            if (! $this->linking->isProviderIdentityUniqueViolation($e)) {
                throw $e;
            }

            // A concurrent winner belongs to another registration attempt. Do not
            // reuse that User with this enrollment's verified TOTP; the new attempt
            // must fail closed and the caller may restart with a fresh OAuth flow.
            throw new \RuntimeException(self::ERROR_CONFLICT, 0, $e);
        }

        $result['user']->flushPermissionCaches();

        $result['provider'] = $pending['provider'];
        $result['provider_user_id'] = $pending['provider_user_id'];

        if (isset($result['registration_data'])) {
            HookManager::doAction('core.auth.record_consents', $result['user'], $result['registration_data'], $now->toIso8601String(), request()->ip());
            HookManager::doAction('core.auth.after_register', $result['user'], [
                'registration_time' => now(),
                'ip_address' => request()->ip(),
                'user_agent' => request()->userAgent(),
                'signup_stage' => 'after_create',
                'registration_data' => $result['registration_data'],
            ]);
        }

        unset($result['registration_data']);

        return $result;
    }

    private function normalizeFields(array $pending, array $input): array
    {
        $name = trim((string) ($input['name'] ?? ''));
        $nickname = trim((string) ($input['nickname'] ?? ''));
        $rawEmail = trim((string) ($input['email'] ?? ''));
        $profileEmail = $pending['provider_profile_email'] ?? $pending['provider_email'] ?? null;
        $registrationEmail = $pending['registration_email'] ?? null;
        $email = strtolower($rawEmail !== '' ? $rawEmail : (string) ($profileEmail ?? ''));
        $language = (string) ($input['language'] ?? 'ko');

        if ($name === '' || mb_strlen($name) > 255
            || ($nickname !== '' && mb_strlen($nickname) > 50)
            || filter_var($email, FILTER_VALIDATE_EMAIL) === false
            || mb_strlen($email) > 255
            || ! $this->accepted($input['agree_terms'] ?? null)
            || ! $this->accepted($input['agree_privacy'] ?? null)
        ) {
            throw new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_INPUT_INVALID);
        }

        if (is_string($registrationEmail) && $registrationEmail !== '' && $email !== strtolower($registrationEmail)) {
            throw new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_EMAIL_MISMATCH);
        }

        return [
            'name' => $name,
            'nickname' => $nickname !== '' ? $nickname : null,
            'email' => $email,
            'language' => in_array($language, config('app.supported_locales', ['ko', 'en']), true)
                ? $language
                : 'ko',
        ];
    }

    private function accepted(mixed $value): bool
    {
        return in_array($value, [true, 1, '1', 'true', 'on', 'yes'], true);
    }

    private function dispatchBeforeRegister(array $fields, ?string $verificationToken = null): void
    {
        $data = [
            'name' => $fields['name'],
            'nickname' => $fields['nickname'],
            'email' => $fields['email'],
            'language' => $fields['language'],
            'agree_terms' => 'accepted',
            'agree_privacy' => 'accepted',
        ];

        if ($verificationToken !== null) {
            $data['verification_token'] = $verificationToken;
        }

        HookManager::doAction('core.auth.before_register', $data, [
            'signup_stage' => 'before_submit',
            'http_method' => 'POST',
            'origin' => 'glitter-social_totp_passkey',
        ]);
    }

    private function signupBeforePolicy(): ?\App\Models\IdentityPolicy
    {
        return $this->identityPolicies->resolve(
            'route',
            'api.auth.register',
            ['signup_stage' => 'before_submit', 'http_method' => 'POST'],
        );
    }

    private function signupAfterPolicy(): ?\App\Models\IdentityPolicy
    {
        return $this->identityPolicies->resolve(
            'hook',
            'core.auth.after_register',
            ['signup_stage' => 'after_create'],
        );
    }

    private function withPendingLock(string $registrationId, string $sessionBinding, callable $callback, bool $registrationSubmit = false): array
    {
        if ($registrationId === '' || $sessionBinding === '') {
            throw $registrationSubmit
                ? new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_PENDING_BINDING_MISMATCH)
                : new \RuntimeException(self::ERROR_INVALID);
        }

        $key = $this->key($registrationId);
        try {
            $lock = Cache::lock($key.':lock', self::LOCK_SECONDS);
            $acquired = $lock->get();
        } catch (\Throwable $e) {
            throw $registrationSubmit
                ? new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_PENDING_LOCK_FAILED, $e)
                : $e;
        }

        if (! $acquired) {
            throw $registrationSubmit
                ? new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_PENDING_LOCK_FAILED)
                : new \RuntimeException(self::ERROR_INVALID);
        }

        try {
            $pending = Cache::get($key);
            if (! is_array($pending) || ! is_string($pending['session_binding_hash'] ?? null)) {
                throw $registrationSubmit
                    ? new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_PENDING_MISSING_OR_EXPIRED)
                    : new \RuntimeException(self::ERROR_INVALID);
            }

            if (! hash_equals($pending['session_binding_hash'], hash('sha256', $sessionBinding))) {
                throw $registrationSubmit
                    ? new SocialRegistrationFailure(self::ERROR_INVALID, SocialRegistrationFailure::REASON_PENDING_BINDING_MISMATCH)
                    : new \RuntimeException(self::ERROR_INVALID);
            }

            return $callback($pending, $key);
        } finally {
            $lock->release();
        }
    }

    private function storePending(string $key, array $pending, \DateTimeInterface $expiresAt): void
    {
        if (! Cache::put($key, $pending, $expiresAt)) {
            throw new \RuntimeException(self::ERROR_INVALID);
        }
    }

    private function key(string $registrationId): string
    {
        return self::CACHE_PREFIX.hash('sha256', $registrationId);
    }

    public function __construct(
        private readonly IdentityVerificationService $identityVerification,
        private readonly IdentityPolicyService $identityPolicies,
        private readonly SocialLoginEligibility $eligibility,
        private readonly SocialTotpService $totp,
        private readonly SocialLinkingService $linking,
        private readonly RoleRepositoryInterface $roles,
        private readonly UserConsentRepositoryInterface $consents,
    ) {}
}
