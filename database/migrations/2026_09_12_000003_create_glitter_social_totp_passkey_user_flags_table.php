<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * 이 플러그인이 소셜 전용(비밀번호 미보유)으로 가입시킨 회원만 행을 갖는다.
     * 행이 없으면 "실사용자가 아는 비밀번호가 있다"로 간주한다(코어 회원가입은
     * 항상 비밀번호를 받으므로 기본값이 true인 셈) — users 테이블 자체는 건드리지
     * 않는 곁다리 테이블 패턴(sirsoft-ecommerce의 ecommerce_user_profiles 참고).
     */
    public function up(): void
    {
        if (Schema::hasTable('glitter_social_totp_passkey_user_flags')) {
            return;
        }

        Schema::create('glitter_social_totp_passkey_user_flags', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->unique()->constrained('users')->cascadeOnDelete();
            $table->boolean('has_real_password')->default(false);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('glitter_social_totp_passkey_user_flags');
    }
};
