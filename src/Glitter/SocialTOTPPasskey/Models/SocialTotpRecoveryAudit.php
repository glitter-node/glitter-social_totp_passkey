<?php

namespace Glitter\SocialTOTPPasskey\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class SocialTotpRecoveryAudit extends Model
{
    public $timestamps = false;
    protected $table = 'glitter_social_totp_passkey_recovery_audits';
    protected $fillable = [
        'request_id', 'actor_user_id', 'action', 'evidence_type', 'evidence_provider_id',
        'target_user_id', 'provider', 'metadata', 'created_at',
    ];
    protected function casts(): array { return ['metadata' => 'array', 'created_at' => 'datetime']; }
    public function request(): BelongsTo { return $this->belongsTo(SocialTotpRecoveryRequest::class, 'request_id'); }
    public function actor(): BelongsTo { return $this->belongsTo(User::class, 'actor_user_id'); }
}
