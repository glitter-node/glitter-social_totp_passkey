<?php

namespace Glitter\SocialTOTPPasskey\Auth;

use App\Enums\IdentityVerificationPurpose;
use App\Enums\IdentityVerificationStatus;
use App\Enums\PermissionType;
use App\Extension\IdentityVerification\IdentityVerificationManager;
use App\Models\IdentityVerificationLog;
use App\Models\User;
use App\Services\IdentityVerificationService;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Glitter\SocialTOTPPasskey\Models\SocialAccount;
use Glitter\SocialTOTPPasskey\Models\SocialLoginTotp;
use Glitter\SocialTOTPPasskey\Models\SocialLoginUserFlag;
use Glitter\SocialTOTPPasskey\Models\SocialTotpRecoveryAudit;
use Glitter\SocialTOTPPasskey\Models\SocialTotpRecoveryGrant;
use Glitter\SocialTOTPPasskey\Models\SocialTotpRecoveryRequest;

/**
 * 소셜 전용 계정의 TOTP 최초 등록 복구를 관리한다.
 *
 * OAuth 성공은 요청 생성의 근거일 뿐이다. core Login-purpose IDV의 검증된
 * 비이메일 challenge와 관리자 권한 승인이 모두 있어야 enrollment 권한이 생긴다.
 * 현재 메일 provider만 설치된 환경에서는 증거 검증과 승인이 의도적으로 실패한다.
 */
final class SocialTotpRecoveryService
{
    private const REQUEST_TTL = 900;
    private const GRANT_TTL = 300;
    private const EVIDENCE_TYPE = 'core_identity_login_non_email';

    public function __construct(
        private readonly IdentityVerificationService $identity,
        private readonly IdentityVerificationManager $manager,
        private readonly SocialLoginEligibility $eligibility,
        private readonly SocialTotpService $totp,
    ) {}

    /** @return array{request_id:string, status:string, challenge_id:?string, expires_at:string} */
    public function startFromOAuth(User $user, string $provider, string $providerUserId, string $binding, string $sessionId, string $userAgent): array
    {
        $requestId = $this->createRequest($user, $provider, $providerUserId, $binding, $sessionId, $userAgent);

        try {
            return $this->startEvidence($requestId, $binding, $sessionId, $userAgent);
        } catch (\Throwable) {
            // 요청은 남기되 challenge/secret/token은 만들지 않는다. 관리자도 검증된
            // evidence 없이는 승인할 수 없으므로 현재 provider 부재 시 fail-closed다.
            $request = $this->findForUser($requestId, $user, $binding, $sessionId, $userAgent);
            return $this->publicState($request, null, $requestId);
        }
    }

    private function createRequest(User $user, string $provider, string $providerUserId, string $binding, string $sessionId, string $userAgent): string
    {
        if ($provider === '' || $providerUserId === '' || $binding === '' || $sessionId === '' || $userAgent === '') {
            throw new \RuntimeException('social_totp_passkey_totp_recovery_unavailable');
        }
        $this->eligibility->assertBaseCanAuthenticate($user);
        $flag = SocialLoginUserFlag::query()->where('user_id', $user->getKey())->first();
        $account = SocialAccount::query()->where('user_id', $user->getKey())
            ->where('provider', $provider)->where('provider_user_id', $providerUserId)->first();
        if ($flag === null || $flag->has_real_password || $account === null || $this->totp->isEnabled($user)) {
            throw new \RuntimeException('social_totp_passkey_totp_recovery_unavailable');
        }

        $publicId = Str::random(48);
        $request = DB::transaction(function () use ($user, $provider, $providerUserId, $binding, $sessionId, $userAgent, $publicId): SocialTotpRecoveryRequest {
            $record = SocialTotpRecoveryRequest::query()->create([
                'public_id_hash' => hash('sha256', $publicId),
                'user_id' => $user->getKey(),
                'provider' => $provider,
                'provider_user_id_hash' => hash('sha256', $provider."\0".$providerUserId),
                'session_binding_hash' => hash('sha256', $binding),
                'session_hash' => hash('sha256', $sessionId),
                'browser_hash' => hash('sha256', $userAgent),
                'status' => 'awaiting_evidence',
                'expires_at' => now()->addSeconds(self::REQUEST_TTL),
            ]);
            $this->audit($record, 'requested', null, null, null);
            return $record;
        });

        return $publicId;
    }

    /** @return array{request_id:string, status:string, challenge_id:?string, provider_id:?string, render_hint:?string, public_payload:array, expires_at:string} */
    public function startEvidence(string $publicId, string $binding, string $sessionId, string $userAgent): array
    {
        $request = $this->findForBinding($publicId, $binding, $sessionId, $userAgent);
        if ($request->expires_at->isPast() || ! in_array($request->status, ['awaiting_evidence', 'evidence_started'], true)) {
            throw new \RuntimeException('social_totp_passkey_totp_recovery_unavailable');
        }

        if ($request->challenge_id !== null) {
            return $this->publicState($request, null, $publicId);
        }

        $provider = $this->trustedProvider();
        $challenge = $this->identity->start(
            IdentityVerificationPurpose::Login->value,
            $request->user,
            [
                'origin_type' => 'route',
                'origin_identifier' => 'glitter.social_totp_passkey.totp_recovery',
                'user_agent' => substr($userAgent, 0, 512),
                'ip_address' => request()->ip(),
            ],
            $provider->getId(),
        );

        DB::transaction(function () use ($request, $challenge, $provider): void {
            $locked = SocialTotpRecoveryRequest::query()->whereKey($request->getKey())->lockForUpdate()->firstOrFail();
            if ($locked->challenge_id !== null || $locked->expires_at->isPast()) {
                throw new \RuntimeException('social_totp_passkey_totp_recovery_unavailable');
            }
            $locked->forceFill([
                'challenge_id' => $challenge->id,
                'evidence_provider_id' => $provider->getId(),
                'evidence_type' => self::EVIDENCE_TYPE,
                'status' => 'evidence_started',
            ])->save();
            $this->audit($locked, 'evidence_requested', null, self::EVIDENCE_TYPE, $provider->getId());
        });

        $request->refresh();
        return $this->publicState($request, $challenge, $publicId);
    }

    /** @param array<string,mixed> $input */
    public function completeEvidence(string $publicId, string $binding, string $sessionId, string $userAgent, array $input): bool
    {
        $request = $this->findForBinding($publicId, $binding, $sessionId, $userAgent);
        if ($request->challenge_id === null || $request->expires_at->isPast() || $request->status !== 'evidence_started') {
            return false;
        }

        $status = $this->identity->getStatus($request->challenge_id);
        if (! is_array($status) || ($status['purpose'] ?? null) !== IdentityVerificationPurpose::Login->value
            || ($status['provider_id'] ?? null) !== $request->evidence_provider_id) {
            return false;
        }

        $result = $this->identity->verify($request->challenge_id, $input, [
            'origin_type' => 'route',
            'origin_identifier' => 'glitter.social_totp_passkey.totp_recovery',
            'user_agent' => substr($userAgent, 0, 512),
            'ip_address' => request()->ip(),
        ]);
        if (! $result->success) {
            return false;
        }

        $verifiedUser = $this->identity->resolveVerifiedUser($request->challenge_id, IdentityVerificationPurpose::Login->value);
        if (! $verifiedUser || (int) $verifiedUser->getKey() !== (int) $request->user_id) {
            return false;
        }

        $log = IdentityVerificationLog::query()->find($request->challenge_id);
        if (! $this->validEvidence($log, $request)) {
            return false;
        }

        DB::transaction(function () use ($request, $log): void {
            $locked = SocialTotpRecoveryRequest::query()->whereKey($request->getKey())->lockForUpdate()->firstOrFail();
            if ($locked->status !== 'evidence_started' || $locked->expires_at->isPast()) {
                throw new \RuntimeException('social_totp_passkey_totp_recovery_unavailable');
            }
            $locked->forceFill([
                'status' => 'evidence_verified',
                'evidence_verified_at' => now(),
                'evidence_provider_id' => $log->provider_id,
                'evidence_type' => self::EVIDENCE_TYPE,
            ])->save();
            $this->audit($locked, 'evidence_verified', null, self::EVIDENCE_TYPE, $log->provider_id);
        });

        return true;
    }

    /** @return array<int,array<string,mixed>> */
    public function adminList(): array
    {
        return SocialTotpRecoveryRequest::query()->with('user')->whereIn('status', ['awaiting_evidence', 'evidence_started', 'evidence_verified', 'approved'])
            ->latest('id')->limit(100)->get()->map(fn (SocialTotpRecoveryRequest $request): array => [
                'request_id' => $request->getKey(), 'user_id' => $request->user_id, 'provider' => $request->provider,
                'status' => $request->status, 'challenge_id' => $request->challenge_id,
                'evidence_type' => $request->evidence_type, 'expires_at' => $request->expires_at?->toIso8601String(),
                'approved_at' => $request->approved_at?->toIso8601String(),
            ])->all();
    }

    public function approve(int $requestId, User $admin): void
    {
        $this->assertAdmin($admin);
        DB::transaction(function () use ($requestId, $admin): void {
            $request = SocialTotpRecoveryRequest::query()->whereKey($requestId)->lockForUpdate()->firstOrFail();
            if ($request->expires_at->isPast() || $request->status !== 'evidence_verified') {
                throw new \RuntimeException('social_totp_passkey_totp_recovery_unavailable');
            }
            $account = SocialAccount::query()->where('user_id', $request->user_id)->where('provider', $request->provider)->first();
            $user = User::query()->find($request->user_id);
            if (! $user || ! $account || ! hash_equals($request->provider_user_id_hash, hash('sha256', $request->provider."\0".$account->provider_user_id))
                || $this->totp->isEnabled($user) || ! $this->validEvidence(IdentityVerificationLog::query()->find($request->challenge_id), $request)) {
                throw new \RuntimeException('social_totp_passkey_totp_recovery_unavailable');
            }
            $request->forceFill(['status' => 'approved', 'approved_by' => $admin->getKey(), 'approved_at' => now()])->save();
            $this->audit($request, 'approved', $admin->getKey(), self::EVIDENCE_TYPE, $request->evidence_provider_id);
        });
    }

    public function reject(int $requestId, User $admin): void
    {
        $this->assertAdmin($admin);
        DB::transaction(function () use ($requestId, $admin): void {
            $request = SocialTotpRecoveryRequest::query()->whereKey($requestId)->lockForUpdate()->firstOrFail();
            if (in_array($request->status, ['consumed', 'rejected'], true) || $request->expires_at->isPast()) {
                throw new \RuntimeException('social_totp_passkey_totp_recovery_unavailable');
            }

            // The schema has no revoked_at column. Remove only grants that have
            // not been consumed, while the request row is locked. A concurrent
            // consumer takes the same request lock first, so either its
            // consumption commits before rejection or rejection prevents it.
            SocialTotpRecoveryGrant::query()
                ->where('request_id', $request->getKey())
                ->whereNull('consumed_at')
                ->delete();

            $request->forceFill(['status' => 'rejected', 'rejected_by' => $admin->getKey(), 'rejected_at' => now(), 'rejection_code' => 'operator_rejected'])->saveOrFail();
            $this->audit($request, 'rejected', $admin->getKey(), null, null);
        });
    }

    /** @return array{request_id:string, grant_token:string, reauth_token:string} */
    public function prepareEnrollment(string $publicId, string $binding, string $sessionId, string $userAgent): array
    {
        $request = $this->findForBinding($publicId, $binding, $sessionId, $userAgent);
        $grant = Str::random(64);
        $reauth = null;
        DB::transaction(function () use ($request, $binding, $sessionId, $userAgent, $grant, &$reauth): void {
            $locked = SocialTotpRecoveryRequest::query()->whereKey($request->getKey())->lockForUpdate()->firstOrFail();
            if ($locked->status !== 'approved' || $locked->expires_at->isPast() || $this->totp->isEnabled($locked->user)) {
                throw new \RuntimeException('social_totp_passkey_totp_recovery_unavailable');
            }
            if (SocialTotpRecoveryGrant::query()->where('request_id', $locked->getKey())->whereNull('consumed_at')->where('expires_at', '>', now())->exists()) {
                throw new \RuntimeException('social_totp_passkey_totp_recovery_unavailable');
            }
            $reauth = $this->totp->issueTrustedEnrollmentReauthentication($locked->user, $sessionId, $userAgent);
            SocialTotpRecoveryGrant::query()->create([
                'grant_hash' => hash('sha256', $grant), 'request_id' => $locked->getKey(), 'user_id' => $locked->user_id,
                'provider' => $locked->provider, 'provider_user_id_hash' => $locked->provider_user_id_hash,
                'session_binding_hash' => $locked->session_binding_hash, 'session_hash' => hash('sha256', $sessionId),
                'browser_hash' => hash('sha256', $userAgent), 'expires_at' => now()->addSeconds(self::GRANT_TTL),
            ]);
            $this->audit($locked, 'grant_issued', null, null, null);
        });
        if (! is_string($reauth)) {
            throw new \RuntimeException('social_totp_passkey_totp_recovery_unavailable');
        }
        return ['request_id' => $publicId, 'grant_token' => $grant, 'reauth_token' => $reauth];
    }

    /**
     * 요청과 grant를 먼저 잠근 뒤 TOTP 저장까지 하나의 transaction으로
     * 완료합니다. 반환값은 true=완료, false=등록 검증 실패, null=복구
     * 요청/grant 또는 transaction 실패입니다.
     */
    public function confirmEnrollment(
        User $user,
        string $publicId,
        string $grant,
        string $binding,
        string $sessionId,
        string $userAgent,
        string $reauthToken,
        string $enrollmentId,
        string $code,
    ): ?bool {
        try {
            $result = DB::transaction(function () use ($user, $publicId, $grant, $binding, $sessionId, $userAgent, $reauthToken, $enrollmentId, $code): ?bool {
                // All recovery completion paths use request -> grant -> user -> TOTP.
                $request = SocialTotpRecoveryRequest::query()
                    ->where('public_id_hash', hash('sha256', $publicId))
                    ->lockForUpdate()
                    ->first();

                if (! $request || (int) $request->user_id !== (int) $user->getKey()
                    || $request->status !== 'approved' || $request->expires_at->isPast()
                    || ! hash_equals($request->session_binding_hash, hash('sha256', $binding))
                    || ! hash_equals($request->session_hash, hash('sha256', $sessionId))
                    || ! hash_equals($request->browser_hash, hash('sha256', $userAgent))) {
                    return null;
                }

                $record = SocialTotpRecoveryGrant::query()
                    ->where('request_id', $request->getKey())
                    ->where('grant_hash', hash('sha256', $grant))
                    ->lockForUpdate()
                    ->first();

                if (! $record || (int) $record->request_id !== (int) $request->getKey()
                    || (int) $record->user_id !== (int) $request->user_id
                    || $record->consumed_at !== null || $record->expires_at->isPast()
                    || ! hash_equals($record->session_binding_hash, hash('sha256', $binding))
                    || ! hash_equals($record->session_hash, hash('sha256', $sessionId))
                    || ! hash_equals($record->browser_hash, hash('sha256', $userAgent))) {
                    return null;
                }

                $lockedUser = User::query()->whereKey($request->user_id)->lockForUpdate()->first();
                if (! $lockedUser || (int) $lockedUser->getKey() !== (int) $user->getKey()) {
                    return null;
                }

                if (! $this->totp->confirmEnrollmentWithinTransaction(
                    $lockedUser, $reauthToken, $sessionId, $userAgent, $enrollmentId, $code,
                )) {
                    return false;
                }

                $record->forceFill(['consumed_at' => now()])->saveOrFail();
                $request->forceFill(['status' => 'consumed', 'consumed_at' => now()])->saveOrFail();
                $this->audit($request, 'enrollment_completed', null, null, null);

                return true;
            });
        } catch (\Throwable) {
            return null;
        }

        if ($result === true) {
            try {
                if (! $this->totp->forgetEnrollmentState($enrollmentId, $reauthToken)) {
                    Log::channel('glitter_social_totp_passkey')->warning('glitter_social_totp_passkey.recovery_cache_cleanup_failed', [
                        'action' => 'complete_totp_recovery',
                    ]);
                }
            } catch (\Throwable) {
                Log::channel('glitter_social_totp_passkey')->warning('glitter_social_totp_passkey.recovery_cache_cleanup_failed', [
                    'action' => 'complete_totp_recovery',
                ]);
            }
        }

        return $result;
    }

    public function consumeGrant(string $publicId, string $grant, string $binding, string $sessionId, string $userAgent): bool
    {
        return (bool) DB::transaction(function () use ($publicId, $grant, $binding, $sessionId, $userAgent): bool {
            // Keep the lock order identical to reject() and prepareEnrollment():
            // request first, then its grant. This serializes request rejection,
            // grant issuance, and grant consumption without a request/grant lock
            // inversion.
            $request = SocialTotpRecoveryRequest::query()
                ->where('public_id_hash', hash('sha256', $publicId))
                ->lockForUpdate()
                ->first();

            if (! $request || $request->status !== 'approved' || $request->expires_at->isPast()
                || ! hash_equals($request->session_binding_hash, hash('sha256', $binding))
                || ! hash_equals($request->session_hash, hash('sha256', $sessionId))
                || ! hash_equals($request->browser_hash, hash('sha256', $userAgent))) {
                return false;
            }

            $record = SocialTotpRecoveryGrant::query()
                ->where('request_id', $request->getKey())
                ->where('grant_hash', hash('sha256', $grant))
                ->lockForUpdate()
                ->first();

            if (! $record || (int) $record->request_id !== (int) $request->getKey() || (int) $record->user_id !== (int) $request->user_id
                || $record->consumed_at !== null || $record->expires_at->isPast()
                || ! hash_equals($record->session_binding_hash, hash('sha256', $binding))
                || ! hash_equals($record->session_hash, hash('sha256', $sessionId)) || ! hash_equals($record->browser_hash, hash('sha256', $userAgent))) {
                return false;
            }
            $record->forceFill(['consumed_at' => now()])->saveOrFail();
            $request->forceFill(['status' => 'consumed', 'consumed_at' => now()])->saveOrFail();
            $this->audit($request, 'enrollment_completed', null, null, null);
            return true;
        });
    }

    public function state(string $publicId, string $binding, string $sessionId, string $userAgent): array
    {
        return $this->publicState($this->findForBinding($publicId, $binding, $sessionId, $userAgent));
    }

    private function findForUser(string $publicId, User $user, string $binding, string $sessionId, string $userAgent): SocialTotpRecoveryRequest
    {
        $request = $this->findForBinding($publicId, $binding, $sessionId, $userAgent);
        if ((int) $request->user_id !== (int) $user->getKey()) throw new \RuntimeException('social_totp_passkey_totp_recovery_unavailable');
        return $request;
    }

    private function findForBinding(string $publicId, string $binding, string $sessionId, string $userAgent): SocialTotpRecoveryRequest
    {
        $request = SocialTotpRecoveryRequest::query()->where('public_id_hash', hash('sha256', $publicId))->first();
        if (!$request || ! hash_equals($request->session_binding_hash, hash('sha256', $binding))
            || ! hash_equals($request->session_hash, hash('sha256', $sessionId)) || ! hash_equals($request->browser_hash, hash('sha256', $userAgent))) {
            throw new \RuntimeException('social_totp_passkey_totp_recovery_unavailable');
        }
        return $request->load('user');
    }

    private function trustedProvider(): \App\Contracts\Extension\IdentityVerificationInterface
    {
        $provider = $this->manager->resolveForPurpose(IdentityVerificationPurpose::Login->value);
        $channels = $provider->getChannels();
        if ($provider->getId() === 'g7:core.mail' || ! $provider->supportsPurpose(IdentityVerificationPurpose::Login->value)
            || ! $provider->isAvailable() || ! is_array($channels) || ! array_filter($channels, static fn (mixed $channel): bool => is_string($channel) && $channel !== 'email')) {
            throw new \RuntimeException('social_totp_passkey_totp_recovery_unavailable');
        }
        return $provider;
    }

    private function validEvidence(?IdentityVerificationLog $log, SocialTotpRecoveryRequest $request): bool
    {
        $purpose = $log?->purpose instanceof \BackedEnum ? $log->purpose->value : (string) ($log?->purpose ?? '');
        return $log !== null && $log->isVerified() && ! $log->isExpired() && $log->verified_at !== null
            && $purpose === IdentityVerificationPurpose::Login->value
            && (int) $log->user_id === (int) $request->user_id
            && $log->provider_id === $request->evidence_provider_id && $log->provider_id !== 'g7:core.mail';
    }

    private function assertAdmin(User $admin): void
    {
        if (! $admin->hasPermission('core.users.update', PermissionType::Admin)) throw new \RuntimeException('social_totp_passkey_totp_recovery_forbidden');
    }

    private function audit(SocialTotpRecoveryRequest $request, string $action, ?int $actor, ?string $type, ?string $provider): void
    {
        $audit = new SocialTotpRecoveryAudit();
        $audit->fill([
            'request_id' => $request->getKey(), 'actor_user_id' => $actor, 'action' => $action,
            'evidence_type' => $type, 'evidence_provider_id' => $provider, 'target_user_id' => $request->user_id,
            'provider' => $request->provider, 'metadata' => ['challenge_id' => $request->challenge_id], 'created_at' => now(),
        ]);
        $audit->saveOrFail();
    }

    private function publicState(SocialTotpRecoveryRequest $request, ?object $challenge = null, ?string $publicId = null): array
    {
        return [
            'request_id' => $publicId ?? '',
            'status' => $request->status, 'challenge_id' => $request->challenge_id,
            'provider_id' => $request->evidence_provider_id, 'render_hint' => $challenge?->renderHint,
            'public_payload' => $challenge?->publicPayload ?? [], 'expires_at' => $request->expires_at->toIso8601String(),
        ];
    }
}
