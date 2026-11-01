<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable('glitter_social_totp_passkey_transitions')) {
            Schema::create('glitter_social_totp_passkey_transitions', function (Blueprint $table): void {
                $table->id();
                $table->foreignId('user_id')->constrained('users', 'id', 'social_totp_passkey_totp_transition_user_foreign')->cascadeOnDelete();
                $table->string('provider', 32);
                $table->string('provider_user_id_hash', 64);
                $table->text('encrypted_provider_user_id');
                $table->foreignId('social_account_id')->constrained('glitter_social_totp_passkey_accounts', 'id', 'social_totp_passkey_totp_transition_account_foreign')->cascadeOnDelete();
                $table->timestamp('cutoff_at');
                $table->timestamp('designated_at');
                $table->string('status', 32)->index('social_totp_passkey_totp_transition_status_index');
                $table->timestamp('started_at')->nullable();
                $table->timestamp('completed_at')->nullable();
                $table->timestamp('expires_at')->nullable()->index('social_totp_passkey_totp_transition_expires_index');
                $table->unsignedSmallInteger('attempts')->default(0);
                $table->timestamp('locked_until')->nullable()->index('social_totp_passkey_totp_transition_locked_index');
                $table->timestamps();
                $table->unique('social_account_id', 'social_totp_passkey_totp_transition_account_unique');
                $table->index(['user_id', 'provider', 'status'], 'social_totp_passkey_totp_transition_user_status_index');
            });
        }

        if (! Schema::hasTable('glitter_social_totp_passkey_transition_grants')) {
            Schema::create('glitter_social_totp_passkey_transition_grants', function (Blueprint $table): void {
                $table->id();
                $table->string('grant_hash', 64)->unique('social_totp_passkey_totp_transition_grant_hash_unique');
                $table->foreignId('transition_id')->constrained('glitter_social_totp_passkey_transitions', 'id', 'social_totp_passkey_totp_transition_grant_transition_foreign')->cascadeOnDelete();
                $table->foreignId('user_id')->constrained('users', 'id', 'social_totp_passkey_totp_transition_grant_user_foreign')->cascadeOnDelete();
                $table->string('provider', 32);
                $table->foreignId('social_account_id')->constrained('glitter_social_totp_passkey_accounts', 'id', 'social_totp_passkey_totp_transition_grant_account_foreign')->cascadeOnDelete();
                $table->string('session_binding_hash', 64);
                $table->string('session_hash', 64);
                $table->string('browser_hash', 64);
                $table->timestamp('expires_at')->index('social_totp_passkey_totp_transition_grant_expires_index');
                $table->timestamp('consumed_at')->nullable();
                $table->timestamps();
                $table->unique('transition_id', 'social_totp_passkey_totp_transition_grant_unique');
            });
        }

        if (! Schema::hasTable('glitter_social_totp_passkey_transition_audits')) {
            Schema::create('glitter_social_totp_passkey_transition_audits', function (Blueprint $table): void {
                $table->id();
                $table->foreignId('transition_id')->constrained('glitter_social_totp_passkey_transitions', 'id', 'social_totp_passkey_totp_transition_audit_transition_foreign')->cascadeOnDelete();
                $table->foreignId('actor_user_id')->nullable()->constrained('users', 'id', 'social_totp_passkey_totp_transition_audit_actor_foreign')->nullOnDelete();
                $table->string('action', 64);
                $table->foreignId('target_user_id')->constrained('users', 'id', 'social_totp_passkey_totp_transition_audit_target_foreign')->cascadeOnDelete();
                $table->string('provider', 32);
                $table->json('metadata')->nullable();
                $table->timestamp('created_at');
                $table->index(['transition_id', 'action'], 'social_totp_passkey_totp_transition_audit_index');
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('glitter_social_totp_passkey_transition_audits');
        Schema::dropIfExists('glitter_social_totp_passkey_transition_grants');
        Schema::dropIfExists('glitter_social_totp_passkey_transitions');
    }
};
