<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('glitter_social_totp_passkey_credentials')) {
            return;
        }

        Schema::create('glitter_social_totp_passkey_credentials', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->comment('패스키 소유 회원')
                ->constrained('users', 'id', 'social_totp_passkey_credential_user_foreign')->cascadeOnDelete();
            $table->string('credential_id_hash', 64)->unique('social_totp_passkey_credential_id_unique');
            $table->text('credential_id')->comment('Base64url 인코딩 Credential ID');
            $table->string('user_handle', 128)->comment('Base64url 인코딩 사용자 핸들');
            $table->longText('credential_record')->comment('WebAuthn 라이브러리 CredentialRecord JSON');
            $table->longText('public_key')->comment('Base64url 인코딩 COSE 공개키');
            $table->unsignedBigInteger('signature_counter')->default(0);
            $table->json('transports')->nullable();
            $table->uuid('aaguid')->nullable();
            $table->string('name', 100);
            $table->boolean('backup_eligible')->nullable();
            $table->boolean('backup_status')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->string('authentication_transaction_hash', 64)->nullable()
                ->index('social_totp_passkey_credential_auth_tx_index');
            $table->string('authentication_purpose', 32)->nullable();
            $table->timestamp('authentication_verified_at')->nullable();
            $table->timestamp('authentication_expires_at')->nullable();
            $table->timestamp('authentication_consumed_at')->nullable();
            $table->timestamps();

            $table->index(['user_id', 'created_at'], 'social_totp_passkey_credential_user_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('glitter_social_totp_passkey_credentials');
    }
};
