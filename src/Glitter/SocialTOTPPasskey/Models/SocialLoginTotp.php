<?php

namespace Glitter\SocialTOTPPasskey\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class SocialLoginTotp extends Model
{
    protected $table = 'glitter_social_totp_passkey_totps';

    protected $fillable = [
        'user_id',
        'encrypted_secret',
        'enabled_at',
        'last_used_counter',
        'failed_attempts',
        'locked_until',
    ];

    protected function casts(): array
    {
        return [
            'enabled_at' => 'datetime',
            'locked_until' => 'datetime',
            'last_used_counter' => 'integer',
            'failed_attempts' => 'integer',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
