<?php

namespace Glitter\SocialTOTPPasskey\Services;

use App\Contracts\Repositories\RoleRepositoryInterface;
use App\Models\User;
use App\Services\PluginSettingsService;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Glitter\SocialTotpPasskey\Vendor\Laravel\Socialite\Contracts\User as SocialiteUser;
use Glitter\SocialTotpPasskey\Vendor\Laravel\Socialite\SocialiteManager;
use Glitter\SocialTotpPasskey\Vendor\Laravel\Socialite\Two\FacebookProvider;
use Glitter\SocialTotpPasskey\Vendor\Laravel\Socialite\Two\GithubProvider;
use Glitter\SocialTotpPasskey\Vendor\Laravel\Socialite\Two\GoogleProvider;
use Glitter\SocialTOTPPasskey\Providers\NaverProvider;
use Glitter\SocialTOTPPasskey\Models\SocialAccount;
use Glitter\SocialTOTPPasskey\Models\SocialLoginLinkNonce;
use Glitter\SocialTOTPPasskey\Models\SocialLoginUserFlag;
use Glitter\SocialTOTPPasskey\Linking\SocialLinkingService;
use Glitter\SocialTOTPPasskey\Support\RedirectPath;
use Glitter\SocialTOTPPasskey\Support\ProviderOrder;
use Glitter\SocialTOTPPasskey\Auth\SocialLoginEligibility;
use Glitter\SocialTOTPPasskey\Auth\SocialAuthCompletion;
use Glitter\SocialTOTPPasskey\Exchange\BoundExchangeService;
use Glitter\SocialTOTPPasskey\Registration\SocialRegistrationService;
use Glitter\SocialTotpPasskey\Vendor\SocialiteProviders\Kakao\KakaoProvider;

/**
 * NAVER/카카오/구글/Facebook/GitHub OAuth 로직 전담 서비스.
 *
 * `SocialiteManager::buildProvider()` 로 provider 인스턴스를 직접 조립한다 — 플러그인
 * 설정(DB)에 저장된 client_id/secret 을 코어 `config/services.php` 에 쓰지 않고
 * 그대로 넘길 수 있어, 코어 설정 파일을 건드리지 않고도(플러그인 격리 원칙) 동적
 * 앱 키 교체가 즉시 반영된다.
 *
 * `Socialite` 파사드는 쓰지 않는다 — socialite 는 플러그인 자체 vendor 에 있어 코어의
 * 패키지 auto-discovery 대상이 아니므로 `SocialiteServiceProvider` 가 등록되지 않고,
 * 파사드 해석 시 `Contracts\Factory is not instantiable` 로 500 이 난다(실측).
 */
class SocialAuthService
{
    public const IDENTIFIER = 'glitter-social_totp_passkey';

    public const PROVIDERS = ['naver', 'kakao', 'google', 'facebook', 'github'];

    /** 연동 nonce 유효시간(분) — 인증된 XHR 발급 → 곧바로 브라우저 이동에 쓰인다 */
    private const LINK_NONCE_TTL_MINUTES = 5;

    /**
     * 신규 가입자 기본 역할 식별자.
     *
     * 코어에는 이 값을 담은 설정·상수가 없고, 회원가입(`AuthService::register`)과 관리자 회원 생성
     * (`UserService::createUser`) 두 경로 모두 `RoleRepositoryInterface::findByIdentifier('user')`
     * 리터럴로 조회한다 — 같은 저장소·같은 식별자를 그대로 따른다.
     */
    private const DEFAULT_ROLE_IDENTIFIER = 'user';

    public function __construct(
        private readonly PluginSettingsService $settings,
        private readonly RoleRepositoryInterface $roleRepository,
        private readonly SocialLoginEligibility $eligibility,
        private readonly SocialLinkingService $linking,
        private readonly SocialAuthCompletion $completion,
        private readonly SocialRegistrationService $registration,
        private readonly BoundExchangeService $exchange,
    ) {}

    public function isEnabled(string $provider): bool
    {
        return (bool) $this->settings->get(self::IDENTIFIER, "{$provider}_enabled", false);
    }

    /** @return array<int, string> */
    public function orderedEnabledProviders(): array
    {
        return ProviderOrder::enabled($this->orderedProviders(), fn (string $provider): bool => $this->isEnabled($provider));
    }

    /** @return array<int, string> */
    public function orderedProviders(): array
    {
        return ProviderOrder::normalize($this->settings->get(self::IDENTIFIER, 'provider_order', self::PROVIDERS));
    }

    /**
     * @throws \RuntimeException 설정이 비어있거나 비활성화된 경우
     */
    public function driverFor(string $provider, ?string $redirectPath = null): \Glitter\SocialTotpPasskey\Vendor\Laravel\Socialite\Two\AbstractProvider
    {
        if (! in_array($provider, self::PROVIDERS, true) || ! $this->isEnabled($provider)) {
            throw new \RuntimeException("provider_disabled:{$provider}");
        }

        $clientId = (string) $this->settings->get(self::IDENTIFIER, "{$provider}_client_id", '');
        $clientSecret = (string) $this->settings->get(self::IDENTIFIER, "{$provider}_client_secret", '');

        if ($clientId === '' || $clientSecret === '') {
            throw new \RuntimeException("provider_not_configured:{$provider}");
        }

        $redirectUrl = url($redirectPath ?? "/api/plugins/".self::IDENTIFIER."/{$provider}/callback");

        $config = [
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'redirect' => $redirectUrl,
            'guzzle' => [
                'connect_timeout' => 10,
                'timeout' => 15,
            ],
        ];

        $providerClass = match ($provider) {
            'naver' => NaverProvider::class,
            'kakao' => KakaoProvider::class,
            'google' => GoogleProvider::class,
            'facebook' => FacebookProvider::class,
            'github' => GithubProvider::class,
        };

        /** @var \Glitter\SocialTotpPasskey\Vendor\Laravel\Socialite\Two\AbstractProvider $driver */
        $driver = (new SocialiteManager(app()))->buildProvider($providerClass, $config);

        return $driver;
    }

    /**
     * Legacy plain-exchange entry point.
     *
     * Social OAuth exchanges must be issued only by
     * SocialTwoFactorService::complete() after a verified Login-purpose
     * challenge, so this method fails closed for compatibility with old callers.
     */
    public function issueExchangeCode(
        User $user,
        string $sessionBinding,
        string $redirectPath = RedirectPath::FALLBACK,
    ): string
    {
        // A plain exchange is not a valid Social OAuth completion path.
        // Only SocialTwoFactorService may create an exchange after a verified
        // Login-purpose challenge.
        throw new \RuntimeException(self::ERROR_TWO_FACTOR_REQUIRED);
    }

    /**
     * 교환코드를 1회만 소비하고, 성공했을 때에만 Sanctum 토큰을 발급한다.
     *
     * DB 조건부 UPDATE의 affected rows로 동시 요청 중 하나만 소비에 성공하게 한다.
     * consume 후 eligibility 또는 token 발급이 실패해도 code는 되살리지 않는다.
     *
     * @return array{token: string, user: User, redirect_path: string}|null
     */
    public function consumeExchangeCode(string $code, string $sessionBinding): ?array
    {
        if ($code === '' || $sessionBinding === '') {
            return null;
        }

        $exchange = $this->exchange->consume($code, $sessionBinding);
        if (! $exchange) {
            return null;
        }

        $user = User::query()->find($exchange->user_id);

        if (! $user) {
            return null;
        }

        // callback 이후 exchange 사이에 status, lock 또는 2FA 설정이 바뀔 수
        // 있으므로 token 발급 직전에 fresh User 로 다시 검사한다.
        $this->eligibility->assertBaseCanAuthenticate($user);

        $hasVerifiedAt = $exchange->second_factor_verified_at !== null;
        $hasChallengeHash = is_string($exchange->second_factor_challenge_hash)
            && preg_match('/^[a-f0-9]{64}$/', $exchange->second_factor_challenge_hash) === 1;

        if ($hasVerifiedAt !== $hasChallengeHash) {
            return null;
        }

        // Every Social OAuth exchange is a plugin-owned authentication session.
        // Do not consult Core's global 2FA setting here: a code without the
        // plugin's Login-purpose completion proof must never issue a token.
        if (! $hasVerifiedAt || ! $hasChallengeHash) {
            return null;
        }

        $token = $this->createAuthToken($user);
        $this->completion->complete($user);

        return [
            'token' => $token,
            'user' => $user,
            'redirect_path' => RedirectPath::sanitize($exchange->redirect_path),
        ];
    }

    private function createAuthToken(User $user): string
    {
        // 코어 로그인(AuthService::login)과 동일한 만료 정책을 따른다.
        $lifetime = (int) g7_core_settings('security.auth_token_lifetime', 30);
        $expiresAt = $lifetime === 0 ? null : now()->addMinutes($lifetime);

        return $user->createToken('auth-token', ['*'], $expiresAt)->plainTextToken;
    }

    public function createLinkNonce(User $user, string $provider): string
    {
        $nonce = Str::random(48);

        SocialLoginLinkNonce::create([
            'nonce' => $nonce,
            'user_id' => $user->id,
            'provider' => $provider,
            'expires_at' => now()->addMinutes(self::LINK_NONCE_TTL_MINUTES),
        ]);

        return $nonce;
    }

    /**
     * nonce 를 1회성으로 소비하고 대상 user_id 를 반환한다. 만료/이미사용/불일치 시 null.
     *
     * 소비는 조건부 UPDATE 한 번으로 한다 — 조회 후 저장하는 방식은 같은 nonce 로 콜백이
     * 동시에 두 번 들어오면 양쪽 다 통과할 수 있다. `used_at IS NULL` 을 UPDATE 의 조건에
     * 두면 영향 행 수가 1인 쪽만 소비에 성공하고 나머지는 0 을 받는다.
     */
    public function consumeLinkNonce(string $nonce, string $provider): ?int
    {
        /** @var SocialLoginLinkNonce|null $record */
        $record = SocialLoginLinkNonce::where('nonce', $nonce)
            ->where('provider', $provider)
            ->whereNull('used_at')
            ->where('expires_at', '>=', now())
            ->first();

        if (! $record) {
            return null;
        }

        $affected = SocialLoginLinkNonce::where('id', $record->id)
            ->whereNull('used_at')
            ->update(['used_at' => now()]);

        return $affected === 1 ? $record->user_id : null;
    }

    /**
     * 제공자가 인증했다고 명시한 이메일만 돌려준다. 그 외(미인증·키 없음·알 수 없는 제공자)는 null.
     *
     * - kakao: `kakao_account.is_email_valid` 와 `is_email_verified` 가 둘 다 true
     * - google: `email_verified` 가 true(bool) 또는 "true"(string)
     * - naver: 기존 계정 자동 연결에는 사용하지 않음
     * - facebook: 자동 기존 계정 이메일 매칭에 사용하지 않음
     * - github: bundled Socialite GithubProvider가 `/user/emails`에서 primary 및 verified인
     *   이메일만 반환한다는 계약에 기반한 유효한 이메일
     *
     * socialiteproviders/kakao 는 매핑 단계에서 같은 판정을 이미 하지만, 그 동작에 기대지 않고
     * raw 응답을 직접 엄격하게 확인한다.
     */
    public function providerVerifiedEmail(string $provider, SocialiteUser $socialUser): ?string
    {
        $email = $socialUser->getEmail();

        if (! is_string($email) || $email === '') {
            return null;
        }

        $raw = method_exists($socialUser, 'getRaw') ? $socialUser->getRaw() : [];

        if (! is_array($raw)) {
            return null;
        }

        $verified = match ($provider) {
            'kakao' => Arr::get($raw, 'kakao_account.is_email_valid') === true
                && Arr::get($raw, 'kakao_account.is_email_verified') === true,
            'google' => in_array(Arr::get($raw, 'email_verified'), [true, 'true'], true),
            'naver' => false,
            'facebook' => false,
            // bundled Laravel Socialite v5.31.0 GithubProvider가 /user/emails에서
            // primary && verified 이메일만 Socialite email로 매핑한다.
            'github' => filter_var($email, FILTER_VALIDATE_EMAIL) !== false
                && ($raw['email'] ?? null) === $email,
            default => false,
        };

        return $verified ? $this->normalizeEmail($email) : null;
    }

    /**
     * Provider profile email used for registration metadata or explicit linking.
     * This is not an existing-account ownership proof for Naver.
     */
    public function providerProfileEmail(string $provider, SocialiteUser $socialUser): ?string
    {
        if ($provider !== 'naver') {
            return $this->providerVerifiedEmail($provider, $socialUser);
        }

        $email = $socialUser->getEmail();
        $raw = method_exists($socialUser, 'getRaw') ? $socialUser->getRaw() : [];

        if (! is_string($email) || $email === '' || ! is_array($raw)) {
            return null;
        }

        return $this->isNaverEmailEligible($email, $raw)
            ? $this->normalizeEmail($email)
            : null;
    }

    /**
     * NAVER has no Google-style email_verified field. Its eligible email must
     * still come from the validated nested profile returned by NAVER itself.
     *
     * @param array<string, mixed> $raw
     */
    private function isNaverEmailEligible(string $email, array $raw): bool
    {
        $profile = Arr::get($raw, 'response');
        $profileId = is_array($profile) ? ($profile['id'] ?? null) : null;
        $profileEmail = is_array($profile) ? ($profile['email'] ?? null) : null;

        return (string) Arr::get($raw, 'resultcode') === '00'
            && is_array($profile)
            && is_string($profileId)
            && trim($profileId) !== ''
            && is_string($profileEmail)
            && filter_var($profileEmail, FILTER_VALIDATE_EMAIL) !== false
            && strtolower(trim($email)) === strtolower(trim($profileEmail));
    }

    /**
     * 로그인 콜백 처리 — 기존 provider identity 매칭 → 신규가입 순으로 판정한다.
     *
     * 이메일은 제공자가 인증한 것만 쓴다(`providerVerifiedEmail`). 미인증 이메일은 이메일이
     * 없는 것으로 취급하므로 기존 회원과 매칭하지 않고, 신규 가입은 대체 이메일로 만든다.
     *
     * @return array<string, mixed>
     */
    public function handleLogin(
        string $provider,
        SocialiteUser $socialUser,
        ?string $sessionBinding = null,
        string $redirectPath = RedirectPath::FALLBACK,
    ): array
    {
        $providerUserId = $this->providerUserId($socialUser);
        $registrationEmail = $this->providerVerifiedEmail($provider, $socialUser);
        $profileEmail = $this->providerProfileEmail($provider, $socialUser);

        $result = DB::transaction(function () use ($provider, $providerUserId, $registrationEmail, $profileEmail, $socialUser): array {
            $existing = $this->linking->findIdentityForUpdate($provider, $providerUserId);

            if ($existing) {
                $user = $existing->user;
                if (! $user) {
                    throw new \RuntimeException('social_totp_passkey_identity_invalid');
                }

                $this->eligibility->assertBaseCanAuthenticate($user);

                return [
                    'user' => $user,
                    'requires_additional_auth' => $this->eligibility->requiresAdditionalAuthentication($user),
                ];
            }

            return [
                'pending_registration' => true,
                'provider' => $provider,
                'provider_user_id' => $providerUserId,
                'provider_profile_email' => $profileEmail,
                'registration_email' => $registrationEmail,
                'display_name' => $socialUser->getName() ?: $socialUser->getNickname(),
            ];
        });

        if (($result['pending_registration'] ?? false) === true) {
            if (! is_string($sessionBinding) || $sessionBinding === '') {
                throw new \RuntimeException('social_totp_passkey_exchange_binding_missing');
            }

            // 신규 가입은 DB transaction 밖에서 opaque pending context만 생성합니다.
            // User/SocialAccount는 consent/필드/IDV 완료 시점에만 만들어집니다.
            $this->eligibility->assertCanCreateSocialUser();

            return [
                'pending_registration' => $this->registration->createPending(
                    $result['provider'],
                    $result['provider_user_id'],
                    $result['provider_profile_email'],
                    $result['registration_email'],
                    $result['display_name'],
                    $sessionBinding,
                    $redirectPath,
                ),
            ];
        }

        return $result;
    }

    public function linkAccount(User $user, string $provider, string $providerUserId, ?string $email): SocialAccount
    {
        $providerUserId = $this->normalizeProviderUserId($providerUserId);

        return $this->linking->attach($user, $provider, $providerUserId, $email);
    }

    public function unlinkAccount(User $user, string $provider): string
    {
        return $this->linking->unlink($user, $provider);
    }

    public function requiresAdditionalAuthentication(User $user): bool
    {
        return $this->eligibility->requiresAdditionalAuthentication($user);
    }

    /**
     * Socialite normalized user 의 provider ID 를 login/link 공통 경로에서 검증합니다.
     */
    public function providerUserId(SocialiteUser $socialUser): string
    {
        $value = $socialUser->getId();

        if (! is_int($value) && ! is_string($value)) {
            throw new \RuntimeException('social_totp_passkey_provider_id_invalid');
        }

        return $this->normalizeProviderUserId($value);
    }

    private function normalizeProviderUserId(int|string $value): string
    {
        $normalized = trim((string) $value);

        if ($normalized === '') {
            throw new \RuntimeException('social_totp_passkey_provider_id_invalid');
        }

        return $normalized;
    }

    public function isProviderIdTakenByAnotherUser(string $provider, string $providerUserId, int $exceptUserId): bool
    {
        return SocialAccount::where('provider', $provider)
            ->where('provider_user_id', $providerUserId)
            ->where('user_id', '!=', $exceptUserId)
            ->exists();
    }

    /**
     * 해제 가능 여부 — "실사용자가 아는 비밀번호"가 없고 다른 연동도 없으면
     * 로그인 수단이 완전히 사라지므로 차단한다.
     *
     * `glitter_social_totp_passkey_user_flags` 에 행이 없으면(=이 플러그인이 만든 소셜 전용
     * 가입자가 아니면) 항상 실비밀번호가 있다고 간주한다 — 코어 회원가입은
     * 항상 비밀번호를 받기 때문이다. 행이 있고 `has_real_password=false` 인
     * 상태에서만 "다른 연동 존재 여부"를 추가로 확인한다. 비밀번호 변경/재설정
     * 시 `PasswordChangedFlagListener` 가 이 행을 지워 true 상태로 전환시킨다.
     */
    public function canUnlink(User $user, string $provider): bool
    {
        $flag = SocialLoginUserFlag::where('user_id', $user->id)->first();
        $hasRealPassword = $flag === null || $flag->has_real_password;

        if ($hasRealPassword) {
            return true;
        }

        return SocialAccount::where('user_id', $user->id)
            ->where('provider', '!=', $provider)
            ->exists();
    }

    private function placeholderEmail(): string
    {
        return 'social-'.Str::random(20).'@no-email.invalid';
    }

    private function normalizeEmail(string $email): string
    {
        return strtolower(trim($email));
    }
}
