<?php

namespace Glitter\SocialTOTPPasskey\Auth;

use App\Enums\PermissionType;
use App\Models\User;
use App\Services\PluginSettingsService;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Glitter\SocialTOTPPasskey\Models\SocialAccount;
use Glitter\SocialTOTPPasskey\Models\SocialLoginTotp;
use Glitter\SocialTOTPPasskey\Models\SocialLoginUserFlag;
use Glitter\SocialTOTPPasskey\Models\SocialTotpTransition;
use Glitter\SocialTOTPPasskey\Models\SocialTotpTransitionAudit;
use Glitter\SocialTOTPPasskey\Models\SocialTotpTransitionGrant;

/**
 * 사전에 확정된 기존 소셜 전용 회원의 일회성 TOTP 전환 경로.
 *
 * OAuth 재인증은 provider 인증 성공을 확인할 뿐이며 MFA/독립 본인확인으로
 * 취급하지 않는다. 실제 전환은 고정 cutoff, 명시 명부, 정책 기간, 계정 상태,
 * browser/session binding과 일회성 grant를 모두 통과해야 한다.
 */
final class SocialTotpTransitionService
{
    public const PERMISSION = 'glitter-social_totp_passkey.totp_transition.manage';
    private const IDENTIFIER = 'glitter-social_totp_passkey';
    private const GRANT_TTL = 300;
    private const OAUTH_TTL = 300;

    public function __construct(
        private readonly PluginSettingsService $settings,
        private readonly SocialLoginEligibility $eligibility,
        private readonly SocialTotpService $totp,
    ) {}

    public function isOpen(): bool
    {
        return $this->windowOpen();
    }

    /** @return array<string,mixed> */
    public function dryRun(User $admin, int $userId, int $socialAccountId): array
    {
        $this->assertManager($admin);
        $account = SocialAccount::query()->find($socialAccountId);
        $user = User::query()->find($userId);
        $reasons = [];
        $cutoff = $this->configuredDate('totp_transition_cutoff_at');
        if (! $account || ! $user || (int) ($account?->user_id ?? 0) !== $userId) $reasons[] = 'account_user_mismatch';
        if (! $cutoff) $reasons[] = 'cutoff_not_configured';
        if ($user && $cutoff && ($user->created_at === null || $user->created_at->greaterThan($cutoff))) $reasons[] = 'user_after_cutoff';
        if ($account && $cutoff && ($account->linked_at === null || $account->linked_at->greaterThan($cutoff))) $reasons[] = 'link_after_cutoff';
        if ($user) {
            try { $this->eligibility->assertBaseCanAuthenticate($user); } catch (\Throwable) { $reasons[] = 'user_not_eligible'; }
            if ($this->totp->isEnabled($user)) $reasons[] = 'totp_already_enabled';
            $flag = SocialLoginUserFlag::query()->where('user_id', $userId)->first();
            if (! $flag || $flag->has_real_password) $reasons[] = 'real_password_present';
        }
        if ($account && SocialTotpTransition::query()->where('social_account_id', $socialAccountId)->exists()) $reasons[] = 'already_designated';
        return ['eligible' => $reasons === [], 'user_id' => $userId, 'social_account_id' => $socialAccountId, 'provider' => $account?->provider, 'reasons' => array_values(array_unique($reasons))];
    }

    public function designate(User $admin, int $userId, int $socialAccountId): SocialTotpTransition
    {
        $this->assertManager($admin);
        $check = $this->dryRun($admin, $userId, $socialAccountId);
        if (! $check['eligible']) throw new \RuntimeException('social_totp_passkey_totp_transition_ineligible');
        $account = SocialAccount::query()->findOrFail($socialAccountId);
        $user = User::query()->findOrFail($userId);
        $cutoff = $this->configuredDate('totp_transition_cutoff_at');
        $expires = $this->configuredDate('totp_transition_end_at');

        return DB::transaction(function () use ($admin, $user, $account, $cutoff, $expires): SocialTotpTransition {
            $locked = SocialAccount::query()->whereKey($account->getKey())->lockForUpdate()->firstOrFail();
            if (SocialTotpTransition::query()->where('social_account_id', $locked->getKey())->lockForUpdate()->exists()) throw new \RuntimeException('social_totp_passkey_totp_transition_ineligible');
            $transition = SocialTotpTransition::query()->create([
                'user_id' => $user->getKey(), 'provider' => $locked->provider,
                'provider_user_id_hash' => hash('sha256', $locked->provider."\0".$locked->provider_user_id),
                'encrypted_provider_user_id' => Crypt::encryptString($locked->provider_user_id),
                'social_account_id' => $locked->getKey(), 'cutoff_at' => $cutoff,
                'designated_at' => now(), 'status' => 'eligible', 'expires_at' => $expires,
            ]);
            $this->audit($transition, 'designated', $admin->getKey());
            return $transition;
        });
    }

    /** @return array<int,array<string,mixed>> */
    public function list(User $admin): array
    {
        $this->assertManager($admin);
        return SocialTotpTransition::query()->latest('id')->limit(500)->get()->map(fn (SocialTotpTransition $row): array => [
            'id' => $row->getKey(), 'user_id' => $row->user_id, 'provider' => $row->provider,
            'social_account_id' => $row->social_account_id, 'status' => $row->status,
            'designated_at' => $row->designated_at?->toIso8601String(), 'expires_at' => $row->expires_at?->toIso8601String(),
            'attempts' => $row->attempts, 'locked_until' => $row->locked_until?->toIso8601String(),
            'completed_at' => $row->completed_at?->toIso8601String(),
        ])->all();
    }

    /** @return array{transition_id:int,grant_token:string,reauth_token:string,user_id:int} */
    public function completeOAuth(string $provider, string $providerUserId, string $binding, string $sessionId, string $userAgent): array
    {
        if (! $this->windowOpen()) throw new \RuntimeException('social_totp_passkey_totp_transition_closed');
        $account = SocialAccount::query()->where('provider', $provider)->where('provider_user_id', $providerUserId)->first();
        if (! $account) throw new \RuntimeException('social_totp_passkey_totp_transition_unavailable');
        $grantToken = Str::random(64);
        $reauthToken = null;

        DB::transaction(function () use ($account, $provider, $providerUserId, $binding, $sessionId, $userAgent, $grantToken, &$reauthToken): void {
            $row = SocialTotpTransition::query()->where('social_account_id', $account->getKey())->lockForUpdate()->first();
            $user = $row?->user;
            if (! $row || ! $user || (int) $account->user_id !== (int) $row->user_id || $row->provider !== $provider || $row->status === 'completed' || $row->expires_at?->isPast()
                || $row->locked_until?->isFuture() || ! hash_equals($row->provider_user_id_hash, hash('sha256', $provider."\0".$providerUserId))
                || ! $this->eligibleNow($row, $user) || ! $this->windowOpen()) {
                throw new \RuntimeException('social_totp_passkey_totp_transition_unavailable');
            }
            $existing = SocialTotpTransitionGrant::query()->where('transition_id', $row->getKey())->lockForUpdate()->first();
            if ($existing && $existing->consumed_at === null && $existing->expires_at->isFuture()) throw new \RuntimeException('social_totp_passkey_totp_transition_unavailable');
            $attempts = (int) $row->attempts + 1;
            $max = max(1, (int) $this->settings->get(self::IDENTIFIER, 'totp_transition_max_attempts', 5));
            if ($attempts > $max) {
                $row->forceFill(['attempts' => $attempts, 'locked_until' => now()->addMinutes(15)])->save();
                throw new \RuntimeException('social_totp_passkey_totp_transition_locked');
            }
            $reauthToken = $this->totp->issueTrustedEnrollmentReauthentication($user, $sessionId, $userAgent);
            $data = [
                'grant_hash' => hash('sha256', $grantToken), 'transition_id' => $row->getKey(), 'user_id' => $row->user_id,
                'provider' => $provider, 'social_account_id' => $account->getKey(), 'session_binding_hash' => hash('sha256', $binding),
                'session_hash' => hash('sha256', $sessionId), 'browser_hash' => hash('sha256', $userAgent),
                'expires_at' => $this->grantExpiry(), 'consumed_at' => null,
            ];
            if ($existing) $existing->forceFill($data)->save(); else SocialTotpTransitionGrant::query()->create($data);
            $row->forceFill(['status' => 'in_progress', 'started_at' => now(), 'attempts' => $attempts])->save();
            $this->audit($row, 'oauth_reauthenticated', null, ['provider_user_id_hash' => hash('sha256', $provider."\0".$providerUserId)]);
        });

        if (! is_string($reauthToken)) throw new \RuntimeException('social_totp_passkey_totp_transition_unavailable');
        $transition = SocialTotpTransition::query()->where('social_account_id', $account->getKey())->firstOrFail();
        return ['transition_id' => (int) $transition->getKey(), 'grant_token' => $grantToken, 'reauth_token' => $reauthToken, 'user_id' => (int) $account->user_id];
    }

    /** Must be called inside the TOTP DB transaction. */
    public function consumeWithinTransaction(int $transitionId, string $grantToken, string $binding, string $sessionId, string $userAgent): bool
    {
        if (! $this->windowOpen()) return false;
        $grant = SocialTotpTransitionGrant::query()->where('transition_id', $transitionId)->where('grant_hash', hash('sha256', $grantToken))->lockForUpdate()->first();
        if (! $grant || $grant->consumed_at !== null || $grant->expires_at->isPast()
            || ! hash_equals($grant->session_binding_hash, hash('sha256', $binding))
            || ! hash_equals($grant->session_hash, hash('sha256', $sessionId))
            || ! hash_equals($grant->browser_hash, hash('sha256', $userAgent))) return false;
        $row = SocialTotpTransition::query()->whereKey($transitionId)->lockForUpdate()->first();
        if (! $row || $row->status !== 'in_progress') return false;
        $grant->forceFill(['consumed_at' => now()])->save();
        $row->forceFill(['status' => 'completed', 'completed_at' => now()])->save();
        $this->audit($row, 'completed', null);
        return true;
    }

    public function setEmergencyStop(User $admin, bool $stopped): void
    {
        $this->assertManager($admin);
        $settings = $this->settings->get(self::IDENTIFIER);
        $settings['totp_transition_emergency_stop'] = $stopped;
        $failure = null;
        if (! $this->settings->save(self::IDENTIFIER, $settings, $failure)) throw new \RuntimeException('social_totp_passkey_totp_transition_settings_failed');
    }

    /** @return array<string,mixed> */
    public function updatePolicy(User $admin, array $input): array
    {
        $this->assertManager($admin);
        if (($input['confirm'] ?? false) !== true) throw new \RuntimeException('social_totp_passkey_totp_transition_confirmation_required');
        $start = trim((string) ($input['start_at'] ?? ''));
        $end = trim((string) ($input['end_at'] ?? ''));
        $cutoff = trim((string) ($input['cutoff_at'] ?? ''));
        $startDate = $this->parseRequired($start);
        $endDate = $this->parseRequired($end);
        $cutoffDate = $this->parseRequired($cutoff);
        if ($endDate->lessThanOrEqualTo($startDate) || (int) $input['max_attempts'] < 1 || (int) $input['max_attempts'] > 20) throw new \RuntimeException('social_totp_passkey_totp_transition_settings_invalid');
        $settings = $this->settings->get(self::IDENTIFIER);
        $settings['totp_transition_enabled'] = (bool) ($input['enabled'] ?? false);
        $settings['totp_transition_cutoff_at'] = $cutoffDate->toIso8601String();
        $settings['totp_transition_start_at'] = $startDate->toIso8601String();
        $settings['totp_transition_end_at'] = $endDate->toIso8601String();
        $settings['totp_transition_max_attempts'] = (int) $input['max_attempts'];
        $failure = null;
        if (! $this->settings->save(self::IDENTIFIER, $settings, $failure)) throw new \RuntimeException('social_totp_passkey_totp_transition_settings_failed');
        return ['enabled' => $settings['totp_transition_enabled'], 'cutoff_at' => $settings['totp_transition_cutoff_at'], 'start_at' => $settings['totp_transition_start_at'], 'end_at' => $settings['totp_transition_end_at'], 'max_attempts' => $settings['totp_transition_max_attempts'], 'emergency_stop' => (bool) ($settings['totp_transition_emergency_stop'] ?? false)];
    }

    public function currentPolicy(User $admin): array
    {
        $this->assertManager($admin);
        return [
            'enabled' => (bool) $this->settings->get(self::IDENTIFIER, 'totp_transition_enabled', false),
            'cutoff_at' => $this->settings->get(self::IDENTIFIER, 'totp_transition_cutoff_at', ''),
            'start_at' => $this->settings->get(self::IDENTIFIER, 'totp_transition_start_at', ''),
            'end_at' => $this->settings->get(self::IDENTIFIER, 'totp_transition_end_at', ''),
            'max_attempts' => (int) $this->settings->get(self::IDENTIFIER, 'totp_transition_max_attempts', 5),
            'emergency_stop' => (bool) $this->settings->get(self::IDENTIFIER, 'totp_transition_emergency_stop', false),
        ];
    }

    public function assertEnrollmentGrant(int $transitionId, string $grantToken, string $binding, string $sessionId, string $userAgent): User
    {
        if (! $this->windowOpen()) throw new \RuntimeException('social_totp_passkey_totp_transition_closed');
        $grant = SocialTotpTransitionGrant::query()->where('transition_id', $transitionId)->where('grant_hash', hash('sha256', $grantToken))->first();
        $row = SocialTotpTransition::query()->with('user')->find($transitionId);
        if (! $grant || ! $row || $grant->consumed_at !== null || $grant->expires_at->isPast() || $row->status !== 'in_progress'
            || ! hash_equals($grant->session_binding_hash, hash('sha256', $binding)) || ! hash_equals($grant->session_hash, hash('sha256', $sessionId))
            || ! hash_equals($grant->browser_hash, hash('sha256', $userAgent)) || ! $this->eligibleNow($row, $row->user)) throw new \RuntimeException('social_totp_passkey_totp_transition_unavailable');
        return $row->user;
    }

    /** @return array<int,array<string,mixed>> */
    public function audits(User $admin, ?int $transitionId = null): array
    {
        $this->assertManager($admin);
        $query = SocialTotpTransitionAudit::query()->latest('id');
        if ($transitionId !== null) $query->where('transition_id', $transitionId);
        return $query->limit(500)->get()->map(fn (SocialTotpTransitionAudit $audit): array => [
            'id' => $audit->getKey(), 'transition_id' => $audit->transition_id, 'actor_user_id' => $audit->actor_user_id,
            'action' => $audit->action, 'target_user_id' => $audit->target_user_id, 'provider' => $audit->provider,
            'created_at' => $audit->created_at?->toIso8601String(),
        ])->all();
    }

    private function eligibleNow(SocialTotpTransition $row, User $user): bool
    {
        try { $this->eligibility->assertBaseCanAuthenticate($user); } catch (\Throwable) { return false; }
        $flag = SocialLoginUserFlag::query()->where('user_id', $user->getKey())->first();
        return $flag !== null && ! $flag->has_real_password && ! $this->totp->isEnabled($user)
            && $row->cutoff_at !== null && $user->created_at?->lessThanOrEqualTo($row->cutoff_at)
            && $row->socialAccount?->linked_at?->lessThanOrEqualTo($row->cutoff_at);
    }

    private function windowOpen(): bool
    {
        if (! (bool) $this->settings->get(self::IDENTIFIER, 'totp_transition_enabled', false)
            || (bool) $this->settings->get(self::IDENTIFIER, 'totp_transition_emergency_stop', false)) return false;
        $start = $this->configuredDate('totp_transition_start_at');
        $end = $this->configuredDate('totp_transition_end_at');
        return $start !== null && $end !== null && now()->betweenIncluded($start, $end);
    }

    private function grantExpiry(): CarbonImmutable
    {
        $end = $this->configuredDate('totp_transition_end_at');
        $ttlEnd = now()->addSeconds(self::GRANT_TTL);
        return $end && $end->lessThan($ttlEnd) ? $end : $ttlEnd;
    }

    private function configuredDate(string $key): ?CarbonImmutable
    {
        $value = trim((string) $this->settings->get(self::IDENTIFIER, $key, ''));
        if ($value === '') return null;
        try { return CarbonImmutable::parse($value); } catch (\Throwable) { return null; }
    }

    private function parseRequired(string $value): CarbonImmutable
    {
        if ($value === '') throw new \RuntimeException('social_totp_passkey_totp_transition_settings_invalid');
        try { return CarbonImmutable::parse($value); } catch (\Throwable) { throw new \RuntimeException('social_totp_passkey_totp_transition_settings_invalid'); }
    }

    private function assertManager(User $admin): void
    {
        if (! $admin->hasPermission(self::PERMISSION, PermissionType::Admin)) throw new \RuntimeException('social_totp_passkey_totp_transition_forbidden');
    }

    /** @param array<string,mixed> $metadata */
    private function audit(SocialTotpTransition $row, string $action, ?int $actor, array $metadata = []): void
    {
        SocialTotpTransitionAudit::query()->create([
            'transition_id' => $row->getKey(), 'actor_user_id' => $actor, 'action' => $action,
            'target_user_id' => $row->user_id, 'provider' => $row->provider, 'metadata' => $metadata, 'created_at' => now(),
        ]);
    }
}
