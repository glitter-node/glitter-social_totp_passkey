<?php

namespace Glitter\SocialTOTPPasskey\Auth;

use DateTimeInterface;

final readonly class PasskeyLoginResult
{
    public const TOTP_REQUIRED = 'totp_required';

    public const PASSWORD_CHANGE_REQUIRED = 'password_change_required';

    public const AUTHENTICATED = 'authenticated';

    /**
     * @param  array<string, mixed>  $data
     */
    private function __construct(
        private string $state,
        private array $data,
    ) {}

    public static function totpRequired(string $pendingId, DateTimeInterface $expiresAt): self
    {
        if ($pendingId === '') {
            throw new \InvalidArgumentException('Passkey login pending identifier is required.');
        }

        return new self(self::TOTP_REQUIRED, [
            'pending_id' => $pendingId,
            'expires_at' => $expiresAt->format(DATE_ATOM),
        ]);
    }

    public static function passwordChangeRequired(
        string $challengeId,
        string $reason,
        bool $canPostpone,
        ?int $postponeDays,
        ?string $expiredAt,
        string $expiresAt,
    ): self {
        if ($challengeId === '' || $reason === '' || $expiresAt === '') {
            throw new \InvalidArgumentException('Password change challenge data is incomplete.');
        }

        return new self(self::PASSWORD_CHANGE_REQUIRED, [
            'challenge_id' => $challengeId,
            'reason' => $reason,
            'can_postpone' => $canPostpone,
            'postpone_days' => $postponeDays,
            'expired_at' => $expiredAt,
            'expires_at' => $expiresAt,
        ]);
    }

    /** @param array<string, mixed> $user */
    public static function authenticated(array $user, string $token, string $redirectPath = '/'): self
    {
        if (! is_string($user['uuid'] ?? null)
            || $user['uuid'] === ''
            || $token === ''
            || $redirectPath === ''
        ) {
            throw new \InvalidArgumentException('Authenticated passkey login data is incomplete.');
        }

        return new self(self::AUTHENTICATED, [
            'user' => $user,
            'token' => $token,
            'redirect_path' => $redirectPath,
        ]);
    }

    public function state(): string
    {
        return $this->state;
    }

    /** @return array<string, mixed> */
    public function data(): array
    {
        return $this->data;
    }
}
