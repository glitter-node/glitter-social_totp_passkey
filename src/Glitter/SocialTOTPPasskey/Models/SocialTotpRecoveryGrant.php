<?php

namespace Glitter\SocialTOTPPasskey\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class SocialTotpRecoveryGrant extends Model
{
    protected $table = 'glitter_social_totp_passkey_recovery_grants';

    protected $fillable = [
        'grant_hash', 'request_id', 'user_id', 'provider', 'provider_user_id_hash',
        'session_binding_hash', 'session_hash', 'browser_hash', 'expires_at', 'consumed_at',
    ];

    protected function casts(): array
    {
        return ['expires_at' => 'datetime', 'consumed_at' => 'datetime'];
    }

    public function request(): BelongsTo { return $this->belongsTo(SocialTotpRecoveryRequest::class, 'request_id'); }
    public function user(): BelongsTo { return $this->belongsTo(User::class); }
}
