<?php

namespace Glitter\SocialTOTPPasskey\Auth;

final class ReauthenticationRequiredException extends \RuntimeException
{
    public function __construct()
    {
        parent::__construct(SocialTotpService::ERROR_REAUTH_REQUIRED);
    }
}
