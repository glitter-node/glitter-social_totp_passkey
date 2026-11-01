<?php

namespace Glitter\SocialTOTPPasskey\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class SocialTotpTransition extends Model
{
    protected $table = 'glitter_social_totp_passkey_transitions';
    protected $fillable = [
        'user_id', 'provider', 'provider_user_id_hash', 'encrypted_provider_user_id',
        'social_account_id', 'cutoff_at', 'designated_at', 'status', 'started_at',
        'completed_at', 'expires_at', 'attempts', 'locked_until',
    ];
    protected function casts(): array
    {
        return [
            'cutoff_at' => 'datetime', 'designated_at' => 'datetime', 'started_at' => 'datetime',
            'completed_at' => 'datetime', 'expires_at' => 'datetime', 'locked_until' => 'datetime',
            'attempts' => 'integer',
        ];
    }
    public function user(): BelongsTo { return $this->belongsTo(User::class); }
    public function socialAccount(): BelongsTo { return $this->belongsTo(SocialAccount::class, 'social_account_id'); }
}
