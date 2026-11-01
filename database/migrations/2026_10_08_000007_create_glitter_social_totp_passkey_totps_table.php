<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('glitter_social_totp_passkey_totps')) {
            return;
        }

        Schema::create('glitter_social_totp_passkey_totps', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->unique('social_totp_passkey_totp_user_unique')
                ->constrained('users', 'id', 'social_totp_passkey_totp_user_foreign')->cascadeOnDelete();
            $table->text('encrypted_secret');
            $table->timestamp('enabled_at')->nullable();
            $table->unsignedBigInteger('last_used_counter')->nullable();
            $table->unsignedTinyInteger('failed_attempts')->default(0);
            $table->timestamp('locked_until')->nullable();
            $table->timestamps();

            $table->index('locked_until', 'social_totp_passkey_totp_lock_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('glitter_social_totp_passkey_totps');
    }
};
