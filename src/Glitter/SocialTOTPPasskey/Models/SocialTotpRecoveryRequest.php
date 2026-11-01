<?php

namespace Glitter\SocialTOTPPasskey\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

final class SocialTotpRecoveryRequest extends Model
{
    protected $table = 'glitter_social_totp_passkey_recovery_requests';

    protected $fillable = [
        'public_id_hash', 'user_id', 'provider', 'provider_user_id_hash',
        'session_binding_hash', 'session_hash', 'browser_hash', 'status',
        'challenge_id', 'evidence_provider_id', 'evidence_type',
        'evidence_verified_at', 'approved_by', 'approved_at', 'rejected_by',
        'rejected_at', 'rejection_code', 'expires_at', 'consumed_at',
    ];

    protected function casts(): array
    {
        return [
            'evidence_verified_at' => 'datetime',
            'approved_at' => 'datetime',
            'rejected_at' => 'datetime',
            'expires_at' => 'datetime',
            'consumed_at' => 'datetime',
        ];
    }

    public function user(): BelongsTo { return $this->belongsTo(User::class); }
    public function approver(): BelongsTo { return $this->belongsTo(User::class, 'approved_by'); }
    public function audits(): HasMany { return $this->hasMany(SocialTotpRecoveryAudit::class, 'request_id'); }
    public function grants(): HasMany { return $this->hasMany(SocialTotpRecoveryGrant::class, 'request_id'); }
}
