<?php

return [
    'channels' => [
        'glitter_social_totp_passkey' => [
            'driver' => 'daily',
            'path' => storage_path('logs/glitter_social_totp_passkey.log'),
            'level' => env('GLITTER_SOCIAL_TOTP_PASSKEY_LOG_LEVEL', 'warning'),
            'days' => 14,
            'replace_placeholders' => true,
        ],
    ],
];
