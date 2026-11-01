# Social registration diagnostics

Failures from `POST /api/plugins/glitter-social_totp_passkey/registration` always
produce a safe `social registration failure` record. The
`glitter_social_totp_passkey_registration_diagnostics_enabled` plugin setting additionally enables
the `social registration diagnostic` record. It defaults to `false` and is not
exposed to the frontend.

Both records contain only the fixed `registration_submit` action, a fixed
stage, a fixed reason, and the exception class. They never record request
fields, email addresses, registration IDs, session or cookie values, OAuth
values, TOTP values, exception messages, or stack traces.

Registration TOTP confirmation failures use the
`registration_totp_confirm` action and one of the `totp_pending`,
`totp_verify`, `totp_enrollment_internal`, `totp_provision_conflict`, or
`totp_provision_internal` stages with the same data restrictions.

OAuth callback resolution failures use the `oauth_callback` or
`oauth_login_resolution` action. They record only the provider, fixed stage,
fixed reason, and exception class. Provider tokens, authorization codes,
profile fields, provider user IDs, and browser or session bindings are never
recorded. Registration-pending storage failures use the fixed
`pending_registration_write_failed` reason.

Disable the setting after the required observation is complete. Enabling or
disabling it does not alter registration, TOTP, account-linking, or token
issuance behavior.
