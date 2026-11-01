# Independence contract

Runtime classes use `Glitter\\SocialTOTPPasskey`, routes use the `glitter-social_totp_passkey` URL prefix, and the browser namespace is `GlitterSocialTOTPPasskey`.

Persistent plugin data uses `glitter_social_totp_passkey_`. Settings, environment variables, cache keys, sessions, events, translations, and log channel identifiers use the product-specific values documented in the README. No migration in this product renames or imports an existing social-login table, and no existing identity is automatically transferred.

The original product is not disabled, updated, or modified by this source package. Activation and hook registration fail closed with a conflict error when `glitter-social_login` or `glitter-social_login_totp` is already active; neither existing product is disabled automatically.
