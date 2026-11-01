<?php

namespace Glitter\SocialTOTPPasskey\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class SocialTotpTransitionAudit extends Model
{
    public $timestamps = false;
    protected $table = 'glitter_social_totp_passkey_transition_audits';
    protected $fillable = ['transition_id', 'actor_user_id', 'action', 'target_user_id', 'provider', 'metadata', 'created_at'];
    protected function casts(): array { return ['metadata' => 'array', 'created_at' => 'datetime']; }
    public function transition(): BelongsTo { return $this->belongsTo(SocialTotpTransition::class, 'transition_id'); }
    public function actor(): BelongsTo { return $this->belongsTo(User::class, 'actor_user_id'); }
}
