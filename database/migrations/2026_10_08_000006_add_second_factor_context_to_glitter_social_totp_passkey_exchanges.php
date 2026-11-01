<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $tableName = 'glitter_social_totp_passkey_exchanges';

        if (! Schema::hasTable($tableName)) {
            return;
        }

        if (! Schema::hasColumn($tableName, 'second_factor_verified_at')) {
            Schema::table($tableName, function (Blueprint $table): void {
                $table->timestamp('second_factor_verified_at')->nullable();
            });
        }

        if (! Schema::hasColumn($tableName, 'second_factor_challenge_hash')) {
            Schema::table($tableName, function (Blueprint $table): void {
                $table->string('second_factor_challenge_hash', 64)->nullable();
            });
        }

        if (! $this->hasChallengeUniqueIndex($tableName)) {
            Schema::table($tableName, function (Blueprint $table): void {
                $table->unique(
                    'second_factor_challenge_hash',
                    'social_totp_passkey_exchange_2fa_challenge_unique',
                );
            });
        }
    }

    public function down(): void
    {
        $tableName = 'glitter_social_totp_passkey_exchanges';

        if (! Schema::hasTable($tableName)) {
            return;
        }

        if ($this->hasChallengeUniqueIndex($tableName)) {
            Schema::table($tableName, function (Blueprint $table): void {
                $table->dropUnique('social_totp_passkey_exchange_2fa_challenge_unique');
            });
        }

        $columns = [];
        if (Schema::hasColumn($tableName, 'second_factor_verified_at')) {
            $columns[] = 'second_factor_verified_at';
        }
        if (Schema::hasColumn($tableName, 'second_factor_challenge_hash')) {
            $columns[] = 'second_factor_challenge_hash';
        }

        if ($columns !== []) {
            Schema::table($tableName, function (Blueprint $table) use ($columns): void {
                $table->dropColumn($columns);
            });
        }
    }

    private function hasChallengeUniqueIndex(string $tableName): bool
    {
        foreach (Schema::getIndexes($tableName) as $index) {
            $metadata = is_object($index) ? get_object_vars($index) : $index;
            if (! is_array($metadata)) {
                continue;
            }

            $metadata = array_change_key_case($metadata, CASE_LOWER);
            if (array_key_exists('name', $metadata)
                && $metadata['name'] === 'social_totp_passkey_exchange_2fa_challenge_unique'
            ) {
                return true;
            }
        }

        return false;
    }
};
