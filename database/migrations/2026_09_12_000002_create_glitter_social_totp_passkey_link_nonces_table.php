<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * 로그인 상태에서 "연동하기" 버튼을 눌러 OAuth 로 나갈 때, 브라우저 전체 이동(GET)에는
     * Authorization 헤더(Sanctum 토큰)를 실어 보낼 수 없다. 대신 인증된 XHR 로 발급받은
     * 1회용 nonce 를 쿼리스트링에 실어 신원을 이어 붙인다 (토큰 자체를 URL에 노출하지 않음).
     */
    public function up(): void
    {
        if (Schema::hasTable('glitter_social_totp_passkey_link_nonces')) {
            return;
        }

        Schema::create('glitter_social_totp_passkey_link_nonces', function (Blueprint $table) {
            $table->id();
            $table->string('nonce', 64)->unique();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->string('provider', 20);
            $table->timestamp('expires_at');
            $table->timestamp('used_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('glitter_social_totp_passkey_link_nonces');
    }
};
