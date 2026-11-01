<?php

namespace Glitter\SocialTOTPPasskey\Passkey;

use App\Models\User;
use Glitter\SocialTOTPPasskey\Models\PasskeyCredential;

final readonly class PasskeyAuthenticationResult
{
    public function __construct(
        public User $user,
        public PasskeyCredential $credential,
        public string $challengeReference,
        public ?VerifiedPasskeyAuthentication $evidence,
    ) {}
}
