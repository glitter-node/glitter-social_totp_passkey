<?php

namespace Glitter\SocialTOTPPasskey\Models;

use Illuminate\Database\Eloquent\Model;

class SocialLoginLinkNonce extends Model
{
    protected $table = 'glitter_social_totp_passkey_link_nonces';

    protected $fillable = [
        'nonce',
        'user_id',
        'provider',
        'expires_at',
        'used_at',
    ];

    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
            'used_at' => 'datetime',
        ];
    }
}
