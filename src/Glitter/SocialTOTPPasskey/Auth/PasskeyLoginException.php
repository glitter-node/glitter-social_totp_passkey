<?php

namespace Glitter\SocialTOTPPasskey\Auth;

final class PasskeyLoginException extends \RuntimeException
{
    /** @var array<string, array{status: int, retryable: bool, new_passkey: bool, message_key: string}> */
    private const DEFINITIONS = [
        'passkey_verification_failed' => [
            'status' => 422, 'retryable' => false, 'new_passkey' => true,
            'message_key' => 'glitter-social_totp_passkey::messages.passkey.failed',
        ],
        'passkey_totp_invalid' => [
            'status' => 422, 'retryable' => true, 'new_passkey' => false,
            'message_key' => 'glitter-social_totp_passkey::messages.passkey.failed',
        ],
        'passkey_totp_enrollment_required' => [
            'status' => 409, 'retryable' => false, 'new_passkey' => true,
            'message_key' => 'glitter-social_totp_passkey::messages.passkey.totp_enrollment_required',
        ],
        'passkey_login_in_progress' => [
            'status' => 409, 'retryable' => true, 'new_passkey' => false,
            'message_key' => 'glitter-social_totp_passkey::messages.passkey.failed',
        ],
        'passkey_login_stale' => [
            'status' => 409, 'retryable' => false, 'new_passkey' => true,
            'message_key' => 'glitter-social_totp_passkey::messages.passkey.failed',
        ],
        'passkey_login_expired' => [
            'status' => 410, 'retryable' => false, 'new_passkey' => true,
            'message_key' => 'glitter-social_totp_passkey::messages.passkey.failed',
        ],
        'passkey_login_unavailable' => [
            'status' => 403, 'retryable' => false, 'new_passkey' => false,
            'message_key' => 'glitter-social_totp_passkey::messages.passkey.failed',
        ],
        'passkey_account_locked' => [
            'status' => 423, 'retryable' => true, 'new_passkey' => true,
            'message_key' => 'glitter-social_totp_passkey::messages.passkey.failed',
        ],
        'passkey_password_change_unavailable' => [
            'status' => 503, 'retryable' => true, 'new_passkey' => true,
            'message_key' => 'glitter-social_totp_passkey::messages.passkey.failed',
        ],
        'passkey_login_temporarily_unavailable' => [
            'status' => 503, 'retryable' => true, 'new_passkey' => true,
            'message_key' => 'glitter-social_totp_passkey::messages.passkey.failed',
        ],
    ];

    private function __construct(
        private readonly string $errorCode,
        private readonly int $httpStatus,
        private readonly bool $retryable,
        private readonly bool $requiresNewPasskey,
        private readonly string $messageKey,
        ?\Throwable $previous = null,
    ) {
        parent::__construct('Passkey login could not be completed.', 0, $previous);
    }

    public static function for(string $errorCode, ?\Throwable $previous = null): self
    {
        $definition = self::DEFINITIONS[$errorCode]
            ?? self::DEFINITIONS['passkey_login_temporarily_unavailable'];

        return new self(
            array_key_exists($errorCode, self::DEFINITIONS)
                ? $errorCode
                : 'passkey_login_temporarily_unavailable',
            $definition['status'],
            $definition['retryable'],
            $definition['new_passkey'],
            $definition['message_key'],
            $previous,
        );
    }

    public function errorCode(): string
    {
        return $this->errorCode;
    }

    public function httpStatus(): int
    {
        return $this->httpStatus;
    }

    public function retryable(): bool
    {
        return $this->retryable;
    }

    public function requiresNewPasskey(): bool
    {
        return $this->requiresNewPasskey;
    }

    public function messageKey(): string
    {
        return $this->messageKey;
    }
}
