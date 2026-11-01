<?php

namespace Glitter\SocialTOTPPasskey\Support;

interface ExtensionCacheVersionInvalidator
{
    public function invalidate(): void;
}
