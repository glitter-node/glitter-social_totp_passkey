# Production deployment runbook

This document describes a future, operator-approved deployment. It does not install, activate, migrate, clear caches, publish assets, change OAuth provider settings, or claim that v1.1.5 is deployed.

## A. Predeployment verification

Before scheduling the update:

- Confirm that the bundled source plugin version is `1.1.5`.
- Confirm that `vendor-bundle.zip` and `vendor-bundle.json` are present and form the verified official bundle pair.
- Run `/usr/local/bin/php83 plugins/_bundled/glitter-social_totp_passkey/tools/vendor-scope.php verify` and confirm that the manifest declares `Glitter\\SocialTotpPasskey\\Vendor`.
- Confirm that `.vendor-bundle-work/` is absent from the bundled source.
- Confirm that a separate backup of the previous bundle pair exists.
- Back up the installed plugin and relevant database state using an operator-approved procedure.
- Check the installed Gnuboard7 version, plugin lifecycle contract, provider settings, maintenance window, and application compatibility.

The previous vendor bundle backup is not sufficient for a complete operational rollback. Installed plugin files, database state, settings, and other runtime state require their own recovery plan.

The read-only source check is:

```bash
bash plugins/_bundled/glitter-social_totp_passkey/docs/verify-production-readonly.sh
```

When dependencies change, rebuild the release archive only through `tools/vendor-scope.php build` after installing the pinned toolchain from `tools/php-scoper/composer.lock`. Do not publish the intermediate archive produced by a raw forced `plugin:vendor-bundle` command.

## B. Existing-plugin update

For an existing installation, and only after separate production approval, the intended update command is:

```bash
/usr/local/bin/php83 artisan plugin:update glitter-social_totp_passkey --source=bundled --vendor-mode=bundled --layout-strategy=keep
```

Run it from the appropriate Gnuboard7 application root. This command has not been executed for v1.1.5 and is an intended deployment procedure, not proof of successful deployment.

Within the previously inspected command contract:

- `--source=bundled` selects the bundled source as the update source.
- `--vendor-mode=bundled` selects the bundled vendor package rather than an automatic mode.
- `--layout-strategy=keep` preserves the existing layout strategy.
- Add `--force` only for an explicitly reviewed same-version recovery; it bypasses the normal version comparison and confirmation.

For a new installation, the current inspected CLI contract is `/usr/local/bin/php83 artisan plugin:install glitter-social_totp_passkey --vendor-mode=bundled`. Installation and update both remain production mutations and are outside this source-build task.

Run migrations only through the approved lifecycle after confirming that every migration creates or alters only `glitter_social_totp_passkey_` tables. Do not run the original product’s migrations, and do not disable or update the original product automatically.

Register these callback paths in each provider console before enabling that provider:

```text
/api/plugins/glitter-social_totp_passkey/naver/callback
/api/plugins/glitter-social_totp_passkey/kakao/callback
/api/plugins/glitter-social_totp_passkey/google/callback
/api/plugins/glitter-social_totp_passkey/facebook/callback
/api/plugins/glitter-social_totp_passkey/github/callback
```

## C. Postdeployment functional checks

The following are required future operational checks after an authorized update. They are not completed by this source-level task:

1. Confirm plugin activation and login page rendering.
2. Confirm the social OAuth callback.
3. Confirm pending registration and identity verification.
4. Confirm QR visibility in the TOTP enrollment screen.
5. Scan the QR code with a real authenticator.
6. Confirm manual secret-key fallback.
7. Confirm TOTP confirmation and account completion.
8. Confirm transactional user, social-account, and TOTP creation.
9. Confirm separate login 2FA for existing social accounts.
10. Confirm invalid and replayed TOTP codes are rejected.
11. Confirm enrollment expiration and lockout behavior.
12. Confirm CSP compatibility with `data:image/svg+xml;base64`.
13. Confirm browser clipboard behavior and manual-copy fallback.
14. Confirm application logs do not disclose TOTP secrets, otpauth URIs, or QR data.

Also verify that the active manifest is `1.1.5`, the active source matches the bundled source, and the login page does not render duplicate provider buttons when both products are present.

The plugin TOTP decision must remain unchanged when Gnuboard7 `security.two_factor_auth` is true or false. The read-only verifier intentionally does not read that core setting as a success criterion.

## D. Failure handling and rollback considerations

Stop deployment when a critical predeployment or postdeployment verification fails. Do not invent a rollback command without verifying the official lifecycle contract.

The previous vendor bundle pair is preserved at:

`/volume1/Gnuboard/7/backups/glitter-social_totp_passkey-v1.0.7-prebundle-20261010/`

That backup contains only the previous `vendor-bundle.zip` and `vendor-bundle.json` files. Restoring those two files alone is not a complete application rollback. Installed plugin files, database changes, settings, caches, sessions, and other runtime state require their own operator-approved recovery plan.
