<?php

namespace Glitter\SocialTOTPPasskey\Passkey;

use App\Models\User;
use DateTimeInterface;
use Glitter\SocialTOTPPasskey\Models\PasskeyCredential;

final readonly class VerifiedPasskeyAuthentication
{
    public function __construct(
        private int $credentialId,
        private int $verifiedUserId,
        private string $transaction,
        private DateTimeInterface $verified,
        private DateTimeInterface $expires,
        private bool $userVerified,
    ) {}

    public function purpose(): string
    {
        return 'login';
    }

    public function provider(): string
    {
        return 'glitter-social_totp-passkey:passkey';
    }

    public function subject(): string
    {
        return (string) $this->credentialId;
    }

    public function transactionId(): string
    {
        return $this->transaction;
    }

    public function userId(): ?int
    {
        return $this->verifiedUserId;
    }

    public function verifiedAt(): DateTimeInterface
    {
        return $this->verified;
    }

    public function expiresAt(): DateTimeInterface
    {
        return $this->expires;
    }

    public function isUserVerified(): bool
    {
        return $this->userVerified;
    }

    public function consume(User $user): void
    {
        $affected = PasskeyCredential::query()
            ->whereKey($this->credentialId)
            ->where('user_id', $user->getKey())
            ->where('authentication_transaction_hash', hash('sha256', $this->transaction))
            ->where('authentication_purpose', 'login')
            ->whereNull('authentication_consumed_at')
            ->where('authentication_expires_at', '>=', now())
            ->update(['authentication_consumed_at' => now()]);

        if ($affected !== 1) {
            throw new \RuntimeException('passkey_authentication_evidence_invalid');
        }
    }

    public function credentialId(): int
    {
        return $this->credentialId;
    }

    public function transaction(): string
    {
        return $this->transaction;
    }
}
