<?php

declare(strict_types=1);

return [
    'profile' => [
        'unlink_blocked_no_password' => "You have no password set and no other linked account, so this can't be unlinked. Set a password first.",
        'unlink_success' => 'Social account unlinked.',
        'operation_failed' => 'The request could not be completed. Please try again.',
    ],
    'too_many_attempts' => 'Too many requests. Please try again in :seconds second(s).',
    'registration_failed' => 'Social registration could not be completed. Please try again.',
    'existing_account_link_required' => 'This social sign-in could not be completed. Sign in to your existing account first, then link the social account.',
    'totp' => [
        'reauthentication_required' => 'Additional re-authentication is required to enroll, change, or disable TOTP. No safe re-authentication path is available in this plugin.',
        'enrollment_success' => 'TOTP has been enabled.',
        'enrollment_failed' => 'TOTP enrollment failed.',
        'disabled' => 'TOTP has been disabled.',
        'disable_failed' => 'TOTP disable failed.',
    ],
    'passkey' => [
        'failed' => 'Passkey verification failed.',
        'credential_missing' => 'No Passkey is registered. Register a new Passkey first.',
        'totp_enrollment_required' => 'TOTP is required by the passkey login policy, but this account has no enrolled TOTP. Use the existing account recovery flow.',
    ],
];
