<?php

declare(strict_types=1);

return [
    'prefix' => 'Glitter\\SocialTotpPasskey\\Vendor',
    'php-version' => '8.2',
    'exclude-namespaces' => [
        '~^App(?:\\\\|$)~',
        '~^Glitter\\\\SocialTOTPPasskey(?:\\\\|$)~',
        '~^GuzzleHttp(?:\\\\|$)~',
        '~^Illuminate(?:\\\\|$)~',
        '~^Plugins\\\\Glitter\\\\SocialTotpPasskey(?:\\\\|$)~',
        '~^Psr(?:\\\\|$)~',
        '~^Symfony\\\\Component\\\\Clock(?:\\\\|$)~',
        '~^Symfony\\\\Component\\\\HttpFoundation(?:\\\\|$)~',
        '~^Symfony\\\\Component\\\\HttpKernel(?:\\\\|$)~',
        '~^Symfony\\\\Component\\\\Mime(?:\\\\|$)~',
        '~^Symfony\\\\Contracts(?:\\\\|$)~',
    ],
    'expose-global-constants' => true,
    'expose-global-classes' => true,
    'expose-global-functions' => true,
];
