# Glitter Social TOTP Passkey

글리터 소셜 TOTP 패스키는 네이버·카카오·구글·페이스북·GitHub 소셜 로그인에 TOTP 필수 추가 인증을 적용하는 독립 보안 인증 플러그인입니다.

Glitter Social TOTP Passkey is an independent social authentication plugin enforcing mandatory TOTP verification for Naver, Kakao, Google, Facebook, and GitHub.

## Product identity

- Plugin ID: `glitter-social_totp_passkey`
- Version: `1.1.6`
- Composer package: `glitter/social-totp-passkey`
- PHP namespace: `Glitter\\SocialTOTPPasskey`
- Service provider: `SocialTOTPPasskeyServiceProvider`
- JavaScript global: `GlitterSocialTOTPPasskey`

This product is a separate fork. It does not read, migrate, or modify the original social-login plugin’s settings, provider identities, sessions, cache keys, or database tables.

## Authentication policy

New users follow `OAuth → provider identity → registration pending → TOTP enrollment → TOTP confirmation → member creation → login`. Existing users follow `OAuth → provider identity → TOTP challenge → login`.

The provider identity key is `(provider, provider_user_id)`. An email match alone never links accounts. OAuth success never creates a final login session before the plugin’s TOTP policy is satisfied. The plugin does not consult Gnuboard7 `security.two_factor_auth`; its mandatory TOTP policy is independent of that core setting.

Passkeys use discoverable WebAuthn credentials and `web-auth/webauthn-lib` 5.3. The relying-party ID and allowed origin come from the configured HTTPS `app.url`. A passkey may independently sign in, re-authenticate a signed-in member, or replace the plugin TOTP step after social OAuth when the corresponding administrator policy is enabled. Social substitution remains bound to the same OAuth pending user.

Passkey registration and deletion require a short-lived re-authentication token. Existing password re-authentication and a verified passkey can issue that token. The passkey master switch defaults off, so upgrading does not activate a new authentication surface.

Bundled third-party classes are isolated under `Glitter\\SocialTotpPasskey\\Vendor`. Gnuboard7 framework classes and shared PSR contracts remain unprefixed. 

## Providers and callback URLs

The API prefix is `/api/plugins/glitter-social_totp_passkey`.

- Naver: `/api/plugins/glitter-social_totp_passkey/naver/callback`
- Kakao: `/api/plugins/glitter-social_totp_passkey/kakao/callback`
- Google: `/api/plugins/glitter-social_totp_passkey/google/callback`
- Facebook: `/api/plugins/glitter-social_totp_passkey/facebook/callback`
- GitHub: `/api/plugins/glitter-social_totp_passkey/github/callback`

Register the exact HTTPS callback URL for each enabled provider in its developer console. This plugin does not alter provider-console settings and does not copy credentials from another plugin.

## Storage and settings isolation

- Database tables use the `glitter_social_totp_passkey_` prefix.
- Settings namespace: `glitter-social_totp_passkey`.
- Settings files: `storage/app/plugins/glitter-social_totp_passkey/`.
- Environment prefix: `GLITTER_SOCIAL_TOTP_PASSKEY_`.
- Cache prefix: `glitter_social_totp_passkey:`.
- Session prefix: `glitter_social_totp_passkey.`.
- Event prefix: `glitter.social_totp_passkey.`.
- Log channel identifier: `glitter_social_totp_passkey`.

Secrets are supplied through the plugin’s own settings lifecycle. Migrations in this directory are definitions only; this task does not execute them.

## Installation and operation

The current Gnuboard7 CLI contract provides an independent install command:

```bash
php artisan plugin:install glitter-social_totp_passkey --vendor-mode=bundled
```

Run it only in an approved maintenance window. It copies this bundled source to the active plugin directory, installs the bundled Composer dependencies, applies the plugin lifecycle, and may change database and runtime state. Review the deployment environment and backup procedures before installation.

For an existing installation, the previously verified bundled update procedure is:

```bash
php artisan plugin:update glitter-social_totp_passkey --source=bundled --vendor-mode=bundled --layout-strategy=keep
```

This is an update command for an existing installation, not a new-installation command. Run it from the appropriate Gnuboard7 application root only during an approved maintenance window. It may modify the installed plugin and application runtime state, so back up the installed plugin and relevant database state first. Use `--force` only for an explicitly reviewed same-version recovery. The update command is an intended deployment procedure, not proof of successful deployment. A known Gnuboard7 core issue may cause bundled updates to fail during staging because the core validates the build-time `g7_version` in `vendor-bundle.json` instead of the extension compatibility constraint in `plugin.json`. Do not modify the Vendor Bundle manifest or bypass compatibility checks to work around this issue. Apply the upstream core fix before retrying the update.

Do not disable the original plugin automatically. Before activation, confirm that only one product owns the intended login buttons and callback URLs. Apply migrations through the normal plugin lifecycle only after separate production approval and verification of the installed Gnuboard7 command contract.

## Security invariants

TOTP secrets are encrypted at rest, codes are validated with the configured validity window, replay counters and attempt limits remain enforced, and recovery/re-registration stays behind the existing identity and approval policies. Diagnostic logs contain only provider, action, stage, reason, and exception class. Tokens, authorization codes, secrets, pending identifiers, session identifiers, user identifiers, email addresses, and OTP codes are not logged.

## Existing product

The original social-login product is not modified by this fork. Existing users and provider identities are not imported automatically. A deliberate, separately reviewed account-linking process is required if the operator later wants users to use this independent product.
