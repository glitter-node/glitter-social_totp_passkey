<?php

namespace Glitter\SocialTOTPPasskey\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class PasskeyCredential extends Model
{
    protected $table = 'glitter_social_totp_passkey_credentials';

    protected $fillable = [
        'user_id', 'credential_id_hash', 'credential_id', 'user_handle',
        'credential_record', 'public_key', 'signature_counter', 'transports',
        'aaguid', 'name', 'backup_eligible', 'backup_status', 'last_used_at',
        'authentication_transaction_hash', 'authentication_purpose',
        'authentication_verified_at', 'authentication_expires_at',
        'authentication_consumed_at',
    ];

    protected function casts(): array
    {
        return [
            'transports' => 'array',
            'signature_counter' => 'integer',
            'backup_eligible' => 'boolean',
            'backup_status' => 'boolean',
            'last_used_at' => 'datetime',
            'authentication_verified_at' => 'datetime',
            'authentication_expires_at' => 'datetime',
            'authentication_consumed_at' => 'datetime',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
