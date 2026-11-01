<?php

namespace Glitter\SocialTOTPPasskey\Auth;

use App\Models\User;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Glitter\SocialTOTPPasskey\Models\SocialLoginTotp;
use Glitter\SocialTOTPPasskey\Models\SocialLoginUserFlag;
use Glitter\SocialTOTPPasskey\Support\TotpQrCode;

final class SocialTotpService
{
    private const PERIOD = 30;
    private const DIGITS = 6;
    private const WINDOW = 1;
    private const MAX_ATTEMPTS = 5;
    private const LOCK_MINUTES = 15;
    private const ENROLLMENT_TTL = 300;
    private const REAUTH_TTL = 300;
    private const REAUTH_PREFIX = 'glitter_social_totp_passkey:totp-reauth:';
    private const ENROLLMENT_PREFIX = 'glitter_social_totp_passkey:totp-enrollment:';
    private const REGISTRATION_ENROLLMENT_PREFIX = 'glitter_social_totp_passkey:totp-registration-enrollment:';
    private const ENROLLMENT_MODE_NEW = 'new';
    private const ENROLLMENT_MODE_REPLACE = 'replace';
    private const SETTINGS_IDENTIFIER = 'glitter-social_totp_passkey';

    public const PROVIDER_ID = 'glitter_social_totp_passkey:totp';
    public const ERROR_REAUTH_REQUIRED = 'social_totp_passkey_totp_reauthentication_required';

    public function reauthenticate(User $user, string $password, string $sessionId, string $userAgent): string
    {
        $flag = SocialLoginUserFlag::query()->where('user_id', $user->getKey())->first();
        if ($flag !== null && ! $flag->has_real_password) {
            throw new \RuntimeException(self::ERROR_REAUTH_REQUIRED);
        }

        if ($password === '' || ! Hash::check($password, (string) $user->password)) {
            throw new \RuntimeException(self::ERROR_REAUTH_REQUIRED);
        }

        $token = Str::random(64);
        $stored = Cache::put($this->reauthKey($token), [
            'user_id' => (int) $user->getKey(),
            'session_hash' => hash('sha256', $sessionId),
            'browser_hash' => hash('sha256', $userAgent),
        ], now()->addSeconds(self::REAUTH_TTL));

        if (! $stored) {
            throw new \RuntimeException(self::ERROR_REAUTH_REQUIRED);
        }

        return $token;
    }

    /**
     * 별도의 신뢰된 본인확인(Login-purpose IDV) 완료 후에만 호출됩니다.
     * 비밀번호 없는 소셜 전용 계정에는 이 메서드 외의 자동 등록 경로를
     * 제공하지 않습니다. 토큰은 브라우저에 반환하지 않고 서버 세션에만
     * 보관하는 호출자가 사용합니다.
     */
    public function issueTrustedEnrollmentReauthentication(
        User $user,
        string $sessionId,
        string $userAgent,
    ): string {
        $token = Str::random(64);
        $stored = Cache::put($this->reauthKey($token), [
            'user_id' => (int) $user->getKey(),
            'session_hash' => hash('sha256', $sessionId),
            'browser_hash' => hash('sha256', $userAgent),
            'trusted_identity' => true,
        ], now()->addSeconds(self::REAUTH_TTL));

        if (! $stored) {
            throw new \RuntimeException(self::ERROR_REAUTH_REQUIRED);
        }

        return $token;
    }

    public function assertReauthentication(
        User $user,
        string $token,
        string $sessionId,
        string $userAgent,
    ): void {
        $this->assertReauth($user, $token, $sessionId, $userAgent);
    }

    /** @return array{enrollment_id: string, manual_key: string, otpauth_uri: string, expires_at: string} */
    public function beginEnrollment(
        User $user,
        string $reauthToken,
        string $sessionId,
        string $userAgent,
        string $currentCode = '',
    ): array
    {
        $this->assertReauth($user, $reauthToken, $sessionId, $userAgent);

        $enrollmentState = $this->authorizeEnrollmentState($user, $currentCode);
        if ($enrollmentState === null) {
            throw new \RuntimeException(self::ERROR_REAUTH_REQUIRED);
        }

        $secret = $this->base32Encode(random_bytes(20));
        $enrollmentId = Str::random(48);
        $expiresAt = now()->addSeconds(self::ENROLLMENT_TTL);

        $stored = Cache::put($this->enrollmentKey($enrollmentId), [
            'user_id' => (int) $user->getKey(),
            'reauth_hash' => hash('sha256', $reauthToken),
            'session_hash' => hash('sha256', $sessionId),
            'browser_hash' => hash('sha256', $userAgent),
            'encrypted_secret' => Crypt::encryptString($secret),
            'enrollment_mode' => $enrollmentState['mode'],
            'totp_state' => $enrollmentState['totp_state'],
        ], $expiresAt);

        if (! $stored) {
            throw new \RuntimeException(self::ERROR_REAUTH_REQUIRED);
        }

        return [
            'enrollment_id' => $enrollmentId,
            'manual_key' => $secret,
            'otpauth_uri' => $this->otpauthUri($user, $secret),
            'expires_at' => $expiresAt->toIso8601String(),
        ];
    }

    public function confirmEnrollment(
        User $user,
        string $reauthToken,
        string $sessionId,
        string $userAgent,
        string $enrollmentId,
        string $code,
    ): bool
    {
        try {
            $this->assertReauth($user, $reauthToken, $sessionId, $userAgent);
        } catch (\Throwable $e) {
            $this->diagnoseConfirmFailure('reauth', 'reauth_invalid', $e);
            throw $e;
        }

        $key = $this->enrollmentKey($enrollmentId);
        $pending = Cache::get($key);

        if (! is_array($pending)
            || (int) ($pending['user_id'] ?? 0) !== (int) $user->getKey()
            || ! hash_equals((string) ($pending['reauth_hash'] ?? ''), hash('sha256', $reauthToken))
            || ! hash_equals((string) ($pending['session_hash'] ?? ''), hash('sha256', $sessionId))
            || ! hash_equals((string) ($pending['browser_hash'] ?? ''), hash('sha256', $userAgent))
            || ! is_string($pending['encrypted_secret'] ?? null)
            || ! $this->validEnrollmentState($pending)
        ) {
            $this->diagnoseConfirmFailure('enrollment', 'missing_or_binding_mismatch');
            return false;
        }

        try {
            $secret = Crypt::decryptString($pending['encrypted_secret']);
        } catch (\Throwable $e) {
            $this->diagnoseConfirmFailure('decrypt', 'secret_decrypt_failed', $e);
            throw $e;
        }

        try {
            $counter = $this->matchingCounter($secret, $code, null);
        } catch (\Throwable $e) {
            $this->diagnoseConfirmFailure('verify_code', 'verification_failed', $e);
            throw $e;
        }
        if ($counter === null) {
            $this->diagnoseConfirmFailure('verify_code', 'code_mismatch');
            return false;
        }

        try {
            $persisted = DB::transaction(function () use ($user, $pending, $counter): bool {
                User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
                $totp = SocialLoginTotp::query()->where('user_id', $user->getKey())->lockForUpdate()->first();
                if (! $this->enrollmentStateMatches($pending, $totp)) {
                    return false;
                }
                if (! $totp) {
                    $totp = new SocialLoginTotp();
                    $totp->user_id = $user->getKey();
                }
                $totp->fill([
                    'encrypted_secret' => $pending['encrypted_secret'],
                    'enabled_at' => now(),
                    'last_used_counter' => $counter,
                    'failed_attempts' => 0,
                    'locked_until' => null,
                ]);
                $totp->saveOrFail();

                return true;
            });
        } catch (\Throwable $e) {
            $this->diagnoseConfirmFailure('persist', 'database_save_failed', $e);
            throw $e;
        }

        if (! $persisted) {
            $this->diagnoseConfirmFailure('persist', 'totp_state_changed');
            return false;
        }

        Cache::forget($key);
        Cache::forget($this->reauthKey($reauthToken));
        $this->diagnoseConfirmFailure('complete', 'success');

        return true;
    }

    /**
     * Confirm diagnostics use a plugin-only, default-off setting. Only fixed
     * stages/reasons and exception classes are emitted; credentials, cache keys,
     * codes, secrets, identifiers, and bindings are never included.
     */
    private function diagnoseConfirmFailure(string $stage, string $reason, ?\Throwable $exception = null): void
    {
        if (! function_exists('g7_plugin_settings')
            || (bool) g7_plugin_settings(self::SETTINGS_IDENTIFIER, 'totp_confirm_diagnostics_enabled', false) !== true
        ) {
            return;
        }

        $context = [
            'stage' => $stage,
            'reason' => $reason,
            'exception' => $exception ? get_class($exception) : null,
        ];

        if ($reason === 'success') {
            Log::channel('glitter_social_totp_passkey')->info('glitter-social_totp_passkey: TOTP confirm diagnostic', $context);

            return;
        }

        Log::channel('glitter_social_totp_passkey')->warning('glitter-social_totp_passkey: TOTP confirm diagnostic', $context);
    }

    /**
     * 복구 완료 호출자가 이미 시작한 transaction 안에서만 등록을 저장합니다.
     * 요청/grant 잠금보다 먼저 별도 transaction을 시작하지 않도록 하며,
     * cache 상태는 호출자가 DB commit 이후에 정리해야 합니다.
     */
    public function confirmEnrollmentWithinTransaction(
        User $user,
        string $reauthToken,
        string $sessionId,
        string $userAgent,
        string $enrollmentId,
        string $code,
    ): bool {
        $this->assertReauth($user, $reauthToken, $sessionId, $userAgent);
        $pending = Cache::get($this->enrollmentKey($enrollmentId));

        if (! is_array($pending)
            || (int) ($pending['user_id'] ?? 0) !== (int) $user->getKey()
            || ! hash_equals((string) ($pending['reauth_hash'] ?? ''), hash('sha256', $reauthToken))
            || ! hash_equals((string) ($pending['session_hash'] ?? ''), hash('sha256', $sessionId))
            || ! hash_equals((string) ($pending['browser_hash'] ?? ''), hash('sha256', $userAgent))
            || ! is_string($pending['encrypted_secret'] ?? null)
            || ! $this->validEnrollmentState($pending)
        ) {
            return false;
        }

        $secret = Crypt::decryptString($pending['encrypted_secret']);
        $counter = $this->matchingCounter($secret, $code, null);
        if ($counter === null) {
            return false;
        }

        $totp = SocialLoginTotp::query()->where('user_id', $user->getKey())->lockForUpdate()->first();
        if (! $this->enrollmentStateMatches($pending, $totp)) {
            return false;
        }

        if (! $totp) {
            $totp = new SocialLoginTotp();
            $totp->user_id = $user->getKey();
        }
        $totp->fill([
            'encrypted_secret' => $pending['encrypted_secret'],
            'enabled_at' => now(),
            'last_used_counter' => $counter,
            'failed_attempts' => 0,
            'locked_until' => null,
        ]);
        $totp->saveOrFail();

        return true;
    }

    public function forgetEnrollmentState(string $enrollmentId, string $reauthToken): bool
    {
        return Cache::forget($this->enrollmentKey($enrollmentId))
            && Cache::forget($this->reauthKey($reauthToken));
    }

    /**
     * 전환 grant 소비와 TOTP 저장을 같은 DB transaction 안에서 완료합니다.
     * callback은 grant 행을 잠그고 성공 여부를 반환해야 하며, 실패하면 TOTP
     * 저장도 rollback되어 부분 활성화를 남기지 않습니다.
     */
    public function confirmEnrollmentWithCommit(
        User $user,
        string $reauthToken,
        string $sessionId,
        string $userAgent,
        string $enrollmentId,
        string $code,
        \Closure $commit,
    ): bool {
        try {
            $this->assertReauth($user, $reauthToken, $sessionId, $userAgent);
            $key = $this->enrollmentKey($enrollmentId);
            $pending = Cache::get($key);
            if (! is_array($pending)
                || (int) ($pending['user_id'] ?? 0) !== (int) $user->getKey()
                || ! hash_equals((string) ($pending['reauth_hash'] ?? ''), hash('sha256', $reauthToken))
                || ! hash_equals((string) ($pending['session_hash'] ?? ''), hash('sha256', $sessionId))
                || ! hash_equals((string) ($pending['browser_hash'] ?? ''), hash('sha256', $userAgent))
                || ! is_string($pending['encrypted_secret'] ?? null)
                || ! $this->validEnrollmentState($pending)) return false;

            $secret = Crypt::decryptString($pending['encrypted_secret']);
            $counter = $this->matchingCounter($secret, $code, null);
            if ($counter === null) return false;

            DB::transaction(function () use ($user, $pending, $counter, $commit): void {
                User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
                $totp = SocialLoginTotp::query()->where('user_id', $user->getKey())->lockForUpdate()->first();
                if (! $this->enrollmentStateMatches($pending, $totp)) {
                    throw new \RuntimeException(self::ERROR_REAUTH_REQUIRED);
                }
                if (! $totp) {
                    $totp = new SocialLoginTotp();
                    $totp->user_id = $user->getKey();
                }
                $totp->fill([
                    'encrypted_secret' => $pending['encrypted_secret'], 'enabled_at' => now(),
                    'last_used_counter' => $counter, 'failed_attempts' => 0, 'locked_until' => null,
                ]);
                $totp->saveOrFail();
                if (! $commit()) throw new \RuntimeException(self::ERROR_REAUTH_REQUIRED);
            });
            Cache::forget($key);
            Cache::forget($this->reauthKey($reauthToken));
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * 신규 소셜 가입용 임시 enrollment를 시작합니다.
     * 아직 User가 존재하지 않으므로 등록 pending ID와 OAuth/browser binding에만
     * 결합하며, secret은 암호화된 cache 값으로만 보관합니다.
     *
     * @return array{enrollment_id: string, manual_key: string, otpauth_uri: string, qr_data_uri: ?string, expires_at: string}
     */
    public function beginRegistrationEnrollment(
        string $registrationId,
        string $provider,
        string $providerUserId,
        string $sessionBinding,
        string $sessionId,
        string $userAgent,
        string $label,
    ): array {
        if ($registrationId === '' || $provider === '' || $providerUserId === ''
            || $sessionBinding === '' || $sessionId === '' || $userAgent === '' || $label === '') {
            throw new \RuntimeException(self::ERROR_REAUTH_REQUIRED);
        }

        $key = $this->registrationEnrollmentKey($registrationId);
        $existing = Cache::get($key);
        if (is_array($existing)
            && $this->registrationEnrollmentBindingMatches(
                $existing,
                $registrationId,
                $provider,
                $providerUserId,
                $sessionBinding,
                $sessionId,
                $userAgent,
            )) {
            return $this->registrationEnrollmentPayload($existing);
        }

        if ($existing !== null) {
            Cache::forget($key);
        }

        $secret = $this->base32Encode(random_bytes(20));
        $enrollmentId = Str::random(48);
        $expiresAt = now()->addSeconds(self::ENROLLMENT_TTL);
        $record = [
            'registration_id_hash' => hash('sha256', $registrationId),
            'enrollment_id' => $enrollmentId,
            'provider' => $provider,
            'provider_user_id_hash' => hash('sha256', $provider."\0".$providerUserId),
            'session_binding_hash' => hash('sha256', $sessionBinding),
            'session_hash' => hash('sha256', $sessionId),
            'browser_hash' => hash('sha256', $userAgent),
            'label' => $label,
            'encrypted_secret' => Crypt::encryptString($secret),
            'expires_at' => $expiresAt->toIso8601String(),
        ];

        if (! Cache::put($key, $record, $expiresAt)) {
            throw new \RuntimeException(self::ERROR_REAUTH_REQUIRED);
        }

        return $this->registrationEnrollmentPayload($record);
    }

    /**
     * 신규가입 enrollment를 검증하고 같은 잠금 안에서 completion을 수행합니다.
     * completion 성공 후에만 enrollment를 소비합니다.
     *
     * @return array<string, mixed>|null
     */
    public function confirmRegistrationEnrollment(
        string $registrationId,
        string $enrollmentId,
        string $provider,
        string $providerUserId,
        string $sessionBinding,
        string $sessionId,
        string $userAgent,
        string $code,
        callable $completion,
    ): ?array {
        if ($registrationId === '' || $enrollmentId === '' || $provider === ''
            || $providerUserId === '' || $sessionBinding === '' || $sessionId === ''
            || $userAgent === '') {
            $this->diagnoseConfirmFailure('registration_input', 'missing_required_argument');
            return null;
        }

        $key = $this->registrationEnrollmentKey($registrationId);
        try {
            $lock = Cache::lock($key.':lock', 10);
            $acquired = $lock->get();
        } catch (\Throwable $e) {
            $this->diagnoseConfirmFailure('registration_lock', 'lock_access_failed', $e);
            throw $e;
        }
        if (! $acquired) {
            $this->diagnoseConfirmFailure('registration_lock', 'lock_not_acquired');
            return null;
        }

        try {
            try {
                $record = Cache::get($key);
            } catch (\Throwable $e) {
                $this->diagnoseConfirmFailure('registration_enrollment', 'cache_read_failed', $e);
                throw $e;
            }
            if (! is_array($record)) {
                $this->diagnoseConfirmFailure('registration_enrollment', 'missing_or_expired');
                return null;
            }

            $bindingFailure = $this->registrationEnrollmentBindingFailureReason(
                $record,
                $registrationId,
                $provider,
                $providerUserId,
                $sessionBinding,
                $sessionId,
                $userAgent,
            );
            if ($bindingFailure !== null) {
                $this->diagnoseConfirmFailure('registration_binding', $bindingFailure);
                return null;
            }

            if (! hash_equals((string) ($record['enrollment_id'] ?? ''), $enrollmentId)) {
                $this->diagnoseConfirmFailure('registration_enrollment', 'enrollment_id_mismatch');
                return null;
            }

            if (! is_string($record['encrypted_secret'] ?? null)) {
                $this->diagnoseConfirmFailure('registration_enrollment', 'encrypted_secret_missing');
                return null;
            }

            try {
                $secret = Crypt::decryptString($record['encrypted_secret']);
            } catch (\Throwable $e) {
                $this->diagnoseConfirmFailure('registration_decrypt', 'secret_decrypt_failed', $e);
                throw $e;
            }

            try {
                $counter = $this->matchingCounter($secret, $code, null);
            } catch (\Throwable $e) {
                $this->diagnoseConfirmFailure('registration_verify_code', 'verification_failed', $e);
                throw $e;
            }
            if ($counter === null) {
                $this->diagnoseConfirmFailure('registration_verify_code', 'code_mismatch');
                return null;
            }

            try {
                $result = $completion($record['encrypted_secret'], $counter);
            } catch (\Throwable $e) {
                $this->diagnoseConfirmFailure('registration_completion', 'completion_failed', $e);
                throw $e;
            }
            try {
                Cache::forget($key);
            } catch (\Throwable $e) {
                $this->diagnoseConfirmFailure('registration_completion', 'enrollment_consume_failed', $e);
                throw $e;
            }

            return $result;
        } finally {
            $lock->release();
        }
    }

    public function disable(
        User $user,
        string $reauthToken,
        string $sessionId,
        string $userAgent,
        string $code,
    ): bool
    {
        $this->assertReauth($user, $reauthToken, $sessionId, $userAgent);
        if ($this->verifyForLogin($user, $code) === null) {
            return false;
        }

        $deleted = SocialLoginTotp::query()->where('user_id', $user->getKey())->delete();
        Cache::forget($this->reauthKey($reauthToken));

        return $deleted === 1;
    }

    public function isEnabled(User $user): bool
    {
        return SocialLoginTotp::query()
            ->where('user_id', $user->getKey())
            ->whereNotNull('enabled_at')
            ->exists();
    }

    /**
     * @return int|null accepted moving counter
     */
    public function verifyForLogin(User $user, string $code): ?int
    {
        $normalized = preg_replace('/\D+/', '', $code) ?? '';
        if (strlen($normalized) !== self::DIGITS) {
            return null;
        }

        return DB::transaction(function () use ($user, $normalized): ?int {
            $totp = SocialLoginTotp::query()
                ->where('user_id', $user->getKey())
                ->whereNotNull('enabled_at')
                ->lockForUpdate()
                ->first();

            if (! $totp || ($totp->locked_until !== null && $totp->locked_until->isFuture())) {
                return null;
            }

            $lastUsed = $totp->last_used_counter;
            $secret = Crypt::decryptString($totp->encrypted_secret);
            $matched = $this->matchingCounter($secret, $normalized, $lastUsed);

            if ($matched === null) {
                $attempts = ((int) $totp->failed_attempts) + 1;
                $totp->failed_attempts = $attempts;
                if ($attempts >= self::MAX_ATTEMPTS) {
                    $totp->locked_until = now()->addMinutes(self::LOCK_MINUTES);
                    $totp->failed_attempts = 0;
                }
                $totp->saveOrFail();

                return null;
            }

            $totp->last_used_counter = $matched;
            $totp->failed_attempts = 0;
            $totp->locked_until = null;
            $totp->saveOrFail();

            return $matched;
        });
    }

    public function challengeReference(User $user, int $counter): string
    {
        $totp = SocialLoginTotp::query()
            ->where('user_id', $user->getKey())
            ->whereNotNull('enabled_at')
            ->value('id');

        if (! $totp) {
            throw new \RuntimeException('social_totp_passkey_totp_not_enabled');
        }

        return self::PROVIDER_ID.':'.$totp.':'.$counter;
    }

    private function code(string $secret, int $counter): string
    {
        $binaryCounter = pack('N2', intdiv($counter, 4294967296), $counter % 4294967296);
        $hash = hash_hmac('sha1', $binaryCounter, $this->base32Decode($secret), true);
        $offset = ord($hash[19]) & 0x0f;
        $value = ((ord($hash[$offset]) & 0x7f) << 24)
            | ((ord($hash[$offset + 1]) & 0xff) << 16)
            | ((ord($hash[$offset + 2]) & 0xff) << 8)
            | (ord($hash[$offset + 3]) & 0xff);

        return str_pad((string) ($value % 10 ** self::DIGITS), self::DIGITS, '0', STR_PAD_LEFT);
    }

    /** The secret argument is decrypted Base32 text, never the stored ciphertext. */
    private function matchingCounter(string $secret, string $code, ?int $lastUsed): ?int
    {
        $normalized = preg_replace('/\D+/', '', $code) ?? '';
        if (strlen($normalized) !== self::DIGITS) {
            return null;
        }

        $counter = intdiv(time(), self::PERIOD);
        for ($offset = -self::WINDOW; $offset <= self::WINDOW; $offset++) {
            $candidate = $counter + $offset;
            if ($candidate < 0 || ($lastUsed !== null && $candidate <= $lastUsed)) {
                continue;
            }
            if (hash_equals($this->code($secret, $candidate), $normalized)) {
                return $candidate;
            }
        }

        return null;
    }

    /** @return array{mode: string, totp_state: ?string}|null */
    private function authorizeEnrollmentState(User $user, string $currentCode): ?array
    {
        return DB::transaction(function () use ($user, $currentCode): ?array {
            User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
            $totp = SocialLoginTotp::query()->where('user_id', $user->getKey())->lockForUpdate()->first();

            if ($totp === null) {
                return ['mode' => self::ENROLLMENT_MODE_NEW, 'totp_state' => null];
            }

            if ($totp->enabled_at === null) {
                return null;
            }

            $normalized = preg_replace('/\D+/', '', $currentCode) ?? '';
            if (strlen($normalized) !== self::DIGITS
                || ($totp->locked_until !== null && $totp->locked_until->isFuture())) {
                return null;
            }

            $secret = Crypt::decryptString($totp->encrypted_secret);
            $matched = $this->matchingCounter($secret, $normalized, $totp->last_used_counter);
            if ($matched === null) {
                $attempts = ((int) $totp->failed_attempts) + 1;
                $totp->failed_attempts = $attempts;
                if ($attempts >= self::MAX_ATTEMPTS) {
                    $totp->locked_until = now()->addMinutes(self::LOCK_MINUTES);
                    $totp->failed_attempts = 0;
                }
                $totp->saveOrFail();

                return null;
            }

            $totp->last_used_counter = $matched;
            $totp->failed_attempts = 0;
            $totp->locked_until = null;
            $totp->saveOrFail();

            return [
                'mode' => self::ENROLLMENT_MODE_REPLACE,
                'totp_state' => $this->totpStateFingerprint($totp),
            ];
        });
    }

    /** @param array<string, mixed> $pending */
    private function validEnrollmentState(array $pending): bool
    {
        $mode = $pending['enrollment_mode'] ?? null;

        return ($mode === self::ENROLLMENT_MODE_NEW && array_key_exists('totp_state', $pending) && $pending['totp_state'] === null)
            || ($mode === self::ENROLLMENT_MODE_REPLACE && is_string($pending['totp_state'] ?? null));
    }

    /** @param array<string, mixed> $pending */
    private function enrollmentStateMatches(array $pending, ?SocialLoginTotp $totp): bool
    {
        if (($pending['enrollment_mode'] ?? null) === self::ENROLLMENT_MODE_NEW) {
            return $totp === null;
        }

        return ($pending['enrollment_mode'] ?? null) === self::ENROLLMENT_MODE_REPLACE
            && $totp !== null
            && $totp->enabled_at !== null
            && is_string($pending['totp_state'] ?? null)
            && hash_equals($pending['totp_state'], $this->totpStateFingerprint($totp));
    }

    private function totpStateFingerprint(SocialLoginTotp $totp): string
    {
        return hash('sha256', implode("\0", [
            (string) $totp->getKey(),
            (string) $totp->getRawOriginal('encrypted_secret'),
            (string) $totp->getRawOriginal('enabled_at'),
        ]));
    }

    private function assertReauth(User $user, string $token, string $sessionId, string $userAgent): void
    {
        $record = Cache::get($this->reauthKey($token));
        if (! is_array($record)
            || (int) ($record['user_id'] ?? 0) !== (int) $user->getKey()
            || ! hash_equals((string) ($record['session_hash'] ?? ''), hash('sha256', $sessionId))
            || ! hash_equals((string) ($record['browser_hash'] ?? ''), hash('sha256', $userAgent))
        ) {
            throw new ReauthenticationRequiredException();
        }
    }

    private function reauthKey(string $token): string
    {
        return self::REAUTH_PREFIX.hash('sha256', $token);
    }

    private function enrollmentKey(string $enrollmentId): string
    {
        return self::ENROLLMENT_PREFIX.hash('sha256', $enrollmentId);
    }

    private function registrationEnrollmentKey(string $registrationId): string
    {
        return self::REGISTRATION_ENROLLMENT_PREFIX.hash('sha256', $registrationId);
    }

    private function registrationEnrollmentBindingMatches(
        array $record,
        string $registrationId,
        string $provider,
        string $providerUserId,
        string $sessionBinding,
        string $sessionId,
        string $userAgent,
    ): bool {
        return hash_equals((string) ($record['registration_id_hash'] ?? ''), hash('sha256', $registrationId))
            && hash_equals((string) ($record['provider'] ?? ''), $provider)
            && hash_equals((string) ($record['provider_user_id_hash'] ?? ''), hash('sha256', $provider."\0".$providerUserId))
            && hash_equals((string) ($record['session_binding_hash'] ?? ''), hash('sha256', $sessionBinding))
            && hash_equals((string) ($record['session_hash'] ?? ''), hash('sha256', $sessionId))
            && hash_equals((string) ($record['browser_hash'] ?? ''), hash('sha256', $userAgent))
            && is_string($record['label'] ?? null)
            && $record['label'] !== '';
    }

    /**
     * Returns only a fixed diagnostic category. Binding values and their hashes
     * must never be exposed to logs.
     *
     * @param array<string, mixed> $record
     */
    private function registrationEnrollmentBindingFailureReason(
        array $record,
        string $registrationId,
        string $provider,
        string $providerUserId,
        string $sessionBinding,
        string $sessionId,
        string $userAgent,
    ): ?string {
        if (! hash_equals((string) ($record['registration_id_hash'] ?? ''), hash('sha256', $registrationId))) {
            return 'registration_id_mismatch';
        }
        if (! hash_equals((string) ($record['provider'] ?? ''), $provider)) {
            return 'provider_mismatch';
        }
        if (! hash_equals((string) ($record['provider_user_id_hash'] ?? ''), hash('sha256', $provider."\0".$providerUserId))) {
            return 'provider_user_mismatch';
        }
        if (! hash_equals((string) ($record['session_binding_hash'] ?? ''), hash('sha256', $sessionBinding))) {
            return 'session_binding_mismatch';
        }
        if (! hash_equals((string) ($record['session_hash'] ?? ''), hash('sha256', $sessionId))) {
            return 'session_mismatch';
        }
        if (! hash_equals((string) ($record['browser_hash'] ?? ''), hash('sha256', $userAgent))) {
            return 'browser_mismatch';
        }
        if (! is_string($record['label'] ?? null) || $record['label'] === '') {
            return 'label_invalid';
        }

        return null;
    }

    /**
     * @param array<string, mixed> $record
     * @return array{enrollment_id: string, manual_key: string, otpauth_uri: string, qr_data_uri: ?string, expires_at: string}
     */
    private function registrationEnrollmentPayload(array $record): array
    {
        $secret = Crypt::decryptString((string) $record['encrypted_secret']);
        $otpauthUri = $this->otpauthUriForLabel((string) $record['label'], $secret);

        return [
            'enrollment_id' => (string) $record['enrollment_id'],
            'manual_key' => $secret,
            'otpauth_uri' => $otpauthUri,
            'qr_data_uri' => TotpQrCode::toDataUri($otpauthUri),
            'expires_at' => (string) $record['expires_at'],
        ];
    }

    private function base32Encode(string $value): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $buffer = 0;
        $bits = 0;
        $result = '';
        for ($i = 0, $length = strlen($value); $i < $length; $i++) {
            $buffer = ($buffer << 8) | ord($value[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $result .= $alphabet[($buffer >> $bits) & 31];
            }
            $buffer = $bits > 0 ? $buffer & ((1 << $bits) - 1) : 0;
        }
        if ($bits > 0) {
            $result .= $alphabet[($buffer << (5 - $bits)) & 31];
        }
        return $result;
    }

    private function otpauthUri(User $user, string $secret): string
    {
        return $this->otpauthUriForLabel((string) $user->email, $secret);
    }

    private function otpauthUriForLabel(string $accountLabel, string $secret): string
    {
        $issuer = rawurlencode((string) config('app.name', 'HubGlitterK'));
        $label = rawurlencode((string) config('app.name', 'HubGlitterK').':'.$accountLabel);
        return 'otpauth://totp/'.$label.'?secret='.rawurlencode($secret)
            .'&issuer='.$issuer.'&algorithm=SHA1&digits=6&period=30';
    }

    private function base32Decode(string $value): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $value = strtoupper(rtrim($value, '='));
        $buffer = 0;
        $bits = 0;
        $result = '';

        for ($i = 0, $length = strlen($value); $i < $length; $i++) {
            $index = strpos($alphabet, $value[$i]);
            if ($index === false) {
                throw new \RuntimeException('social_totp_passkey_totp_secret_invalid');
            }
            $buffer = ($buffer << 5) | $index;
            $bits += 5;
            if ($bits >= 8) {
                $bits -= 8;
                $result .= chr(($buffer >> $bits) & 0xff);
                $buffer = $bits > 0 ? $buffer & ((1 << $bits) - 1) : 0;
            }
        }

        return $result;
    }
}
