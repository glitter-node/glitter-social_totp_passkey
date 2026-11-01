<?php

namespace Glitter\SocialTOTPPasskey\Models;

use Illuminate\Database\Eloquent\Model;

class SocialLoginUserFlag extends Model
{
    protected $table = 'glitter_social_totp_passkey_user_flags';

    protected $fillable = [
        'user_id',
        'has_real_password',
    ];

    protected function casts(): array
    {
        return [
            'has_real_password' => 'boolean',
        ];
    }
}
