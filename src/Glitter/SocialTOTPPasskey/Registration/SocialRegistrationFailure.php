<?php

namespace Glitter\SocialTOTPPasskey\Registration;

final class SocialRegistrationFailure extends \RuntimeException
{
    public const REASON_PENDING_MISSING_OR_EXPIRED = 'pending_missing_or_expired';
    public const REASON_PENDING_BINDING_MISMATCH = 'pending_binding_mismatch';
    public const REASON_PENDING_LOCK_FAILED = 'pending_lock_failed';
    public const REASON_PENDING_WRITE_FAILED = 'pending_write_failed';
    public const REASON_EMAIL_MISMATCH = 'email_mismatch';
    public const REASON_INPUT_INVALID = 'input_invalid';
    public const REASON_IDV_FAILED = 'idv_failed';
    public const REASON_HOOK_FAILED = 'hook_failed';
    public const REASON_AUTO_LINK_NOT_ALLOWED = 'auto_link_not_allowed';
    public const REASON_TOTP_PENDING_INVALID = 'totp_pending_invalid';
    public const REASON_TOTP_ENROLLMENT_INVALID = 'totp_enrollment_invalid';
    public const REASON_TOTP_ENROLLMENT_FAILED = 'totp_enrollment_failed';
    public const REASON_TOTP_PROVISION_CONFLICT = 'totp_provision_conflict';
    public const REASON_TOTP_PROVISION_FAILED = 'totp_provision_failed';
    public const REASON_UNKNOWN = 'unknown';

    private const REASONS = [
        self::REASON_PENDING_MISSING_OR_EXPIRED,
        self::REASON_PENDING_BINDING_MISMATCH,
        self::REASON_PENDING_LOCK_FAILED,
        self::REASON_PENDING_WRITE_FAILED,
        self::REASON_EMAIL_MISMATCH,
        self::REASON_INPUT_INVALID,
        self::REASON_IDV_FAILED,
        self::REASON_HOOK_FAILED,
        self::REASON_AUTO_LINK_NOT_ALLOWED,
        self::REASON_TOTP_PENDING_INVALID,
        self::REASON_TOTP_ENROLLMENT_INVALID,
        self::REASON_TOTP_ENROLLMENT_FAILED,
        self::REASON_TOTP_PROVISION_CONFLICT,
        self::REASON_TOTP_PROVISION_FAILED,
        self::REASON_UNKNOWN,
    ];

    public readonly string $reason;

    public function __construct(string $message, string $reason, ?\Throwable $previous = null)
    {
        $this->reason = in_array($reason, self::REASONS, true) ? $reason : self::REASON_UNKNOWN;
        parent::__construct($message, 0, $previous);
    }
}
