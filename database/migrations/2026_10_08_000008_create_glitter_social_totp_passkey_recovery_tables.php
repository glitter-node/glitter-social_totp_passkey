<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable('glitter_social_totp_passkey_recovery_requests')) {
            Schema::create('glitter_social_totp_passkey_recovery_requests', function (Blueprint $table): void {
                $table->id();
                $table->string('public_id_hash', 64)->unique('social_totp_passkey_totp_recovery_public_unique');
                $table->foreignId('user_id')->constrained('users', 'id', 'social_totp_passkey_totp_recovery_user_foreign')->cascadeOnDelete();
                $table->string('provider', 32);
                $table->string('provider_user_id_hash', 64);
                $table->string('session_binding_hash', 64);
                $table->string('session_hash', 64);
                $table->string('browser_hash', 64);
                $table->string('status', 32)->index('social_totp_passkey_totp_recovery_status_index');
                $table->string('challenge_id', 64)->nullable()->index('social_totp_passkey_totp_recovery_challenge_index');
                $table->string('evidence_provider_id', 128)->nullable();
                $table->string('evidence_type', 64)->nullable();
                $table->timestamp('evidence_verified_at')->nullable();
                $table->foreignId('approved_by')->nullable()->constrained('users', 'id', 'social_totp_passkey_totp_recovery_approved_foreign')->nullOnDelete();
                $table->timestamp('approved_at')->nullable();
                $table->foreignId('rejected_by')->nullable()->constrained('users', 'id', 'social_totp_passkey_totp_recovery_rejected_foreign')->nullOnDelete();
                $table->timestamp('rejected_at')->nullable();
                $table->string('rejection_code', 64)->nullable();
                $table->timestamp('expires_at')->index('social_totp_passkey_totp_recovery_expires_index');
                $table->timestamp('consumed_at')->nullable();
                $table->timestamps();
                $table->index(['user_id', 'provider', 'status'], 'social_totp_passkey_totp_recovery_user_status_index');
            });
        }

        if (! Schema::hasTable('glitter_social_totp_passkey_recovery_grants')) {
            Schema::create('glitter_social_totp_passkey_recovery_grants', function (Blueprint $table): void {
                $table->id();
                $table->string('grant_hash', 64)->unique('social_totp_passkey_totp_recovery_grant_unique');
                $table->foreignId('request_id')->constrained('glitter_social_totp_passkey_recovery_requests', 'id', 'social_totp_passkey_totp_recovery_grant_request_foreign')->cascadeOnDelete();
                $table->foreignId('user_id')->constrained('users', 'id', 'social_totp_passkey_totp_recovery_grant_user_foreign')->cascadeOnDelete();
                $table->string('provider', 32);
                $table->string('provider_user_id_hash', 64);
                $table->string('session_binding_hash', 64);
                $table->string('session_hash', 64);
                $table->string('browser_hash', 64);
                $table->timestamp('expires_at')->index('social_totp_passkey_totp_recovery_grant_expires_index');
                $table->timestamp('consumed_at')->nullable();
                $table->timestamps();
            });
        }

        if (! Schema::hasTable('glitter_social_totp_passkey_recovery_audits')) {
            Schema::create('glitter_social_totp_passkey_recovery_audits', function (Blueprint $table): void {
                $table->id();
                $table->foreignId('request_id')->constrained('glitter_social_totp_passkey_recovery_requests', 'id', 'social_totp_passkey_totp_recovery_audit_request_foreign')->cascadeOnDelete();
                $table->foreignId('actor_user_id')->nullable()->constrained('users', 'id', 'social_totp_passkey_totp_recovery_audit_actor_foreign')->nullOnDelete();
                $table->string('action', 64);
                $table->string('evidence_type', 64)->nullable();
                $table->string('evidence_provider_id', 128)->nullable();
                $table->foreignId('target_user_id')->constrained('users', 'id', 'social_totp_passkey_totp_recovery_audit_target_foreign')->cascadeOnDelete();
                $table->string('provider', 32);
                $table->json('metadata')->nullable();
                $table->timestamp('created_at');
                $table->index(['request_id', 'action'], 'social_totp_passkey_totp_recovery_audit_index');
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('glitter_social_totp_passkey_recovery_audits');
        Schema::dropIfExists('glitter_social_totp_passkey_recovery_grants');
        Schema::dropIfExists('glitter_social_totp_passkey_recovery_requests');
    }
};
