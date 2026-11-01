<?php

namespace Glitter\SocialTOTPPasskey\Passkey;

final class PasskeyManagementException extends \RuntimeException
{
    /** @var array<string, int> */
    private const HTTP_STATUSES = [
        'passkey_reauthentication_required' => 403,
        'passkey_last_authenticator' => 409,
        'passkey_credential_unavailable' => 404,
        'passkey_invalid_request' => 422,
        'passkey_management_unavailable' => 503,
    ];

    private function __construct(
        private readonly string $errorCode,
        private readonly int $httpStatus,
        ?\Throwable $previous = null,
    ) {
        parent::__construct('Passkey management operation could not be completed.', 0, $previous);
    }

    public static function for(string $errorCode, ?\Throwable $previous = null): self
    {
        $safeErrorCode = array_key_exists($errorCode, self::HTTP_STATUSES)
            ? $errorCode
            : 'passkey_management_unavailable';

        return new self($safeErrorCode, self::HTTP_STATUSES[$safeErrorCode], $previous);
    }

    public function errorCode(): string
    {
        return $this->errorCode;
    }

    public function httpStatus(): int
    {
        return $this->httpStatus;
    }
}
