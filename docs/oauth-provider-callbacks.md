# OAuth provider callback guide

Use the callback URI for the new product, not the callback URI of any other social-login installation:

```text
https://{site-host}/api/plugins/glitter-social_totp_passkey/naver/callback
https://{site-host}/api/plugins/glitter-social_totp_passkey/kakao/callback
https://{site-host}/api/plugins/glitter-social_totp_passkey/google/callback
https://{site-host}/api/plugins/glitter-social_totp_passkey/facebook/callback
https://{site-host}/api/plugins/glitter-social_totp_passkey/github/callback
```

The provider client ID and secret are entered in this plugin’s own settings namespace. State, PKCE where supported, callback validation, and browser binding are product-local. Provider user identity is `(provider, provider_user_id)`; profile email is metadata and never replaces that identity key.
