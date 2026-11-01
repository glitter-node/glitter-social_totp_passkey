<?php

namespace Glitter\SocialTOTPPasskey\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class SocialTotpTransitionGrant extends Model
{
    protected $table = 'glitter_social_totp_passkey_transition_grants';
    protected $fillable = [
        'grant_hash', 'transition_id', 'user_id', 'provider', 'social_account_id',
        'session_binding_hash', 'session_hash', 'browser_hash', 'expires_at', 'consumed_at',
    ];
    protected function casts(): array { return ['expires_at' => 'datetime', 'consumed_at' => 'datetime']; }
    public function transition(): BelongsTo { return $this->belongsTo(SocialTotpTransition::class, 'transition_id'); }
    public function user(): BelongsTo { return $this->belongsTo(User::class); }
}
