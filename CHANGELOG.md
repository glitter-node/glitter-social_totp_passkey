# Changelog

## [1.1.6] - 2026-11-02

### Fixed
- Load the bundled Composer autoloader from the plugin entrypoint so bundled plugin discovery can resolve the implementation class before the core extension autoload cache is rebuilt.

No database schema changes.

## 1.1.5

### Fixed

- Start the API session before CSRF validation on the Passkey Credential rename route.
- Use distinct Form input names for Passkey registration, Credential rename, and social registration while keeping the server `name` request field unchanged.

## 1.1.4

### Fixed

- When a saved Provider display order actually changes, the server layout cache is cleared before the core extension cache version is advanced, so newly opened login, registration, and profile pages request the latest order.
- Added request-scoped change tracking so saves with the same normalized order, or without `provider_order`, do not advance the global cache version.
- Scoped bundled third-party dependencies under `Glitter\\SocialTotpPasskey\\Vendor` so the plugin autoloader cannot claim core or other-extension FQCNs, including incompatible `brick/math` releases.

### Security

- WebAuthn authentication now fails closed when Credential security-state persistence returns `false` or throws after assertion validation; `PasskeyAuthenticationResult` is not created until the save succeeds.

### Tests

- Added isolated unit and static contract tests covering Provider-order change detection, cleanup after save failure, server-cache and global-version update ordering, and the core Trait call contract.
- Added isolated execution tests covering successful Credential persistence, a `false` save result, and a save exception.
- Added deterministic scoped-Vendor build verification and two-order autoloader regression coverage for WebAuthn, CBOR, COSE, QR, Socialite, and differing Brick Math releases.

## 1.1.3

### Fixed

- Safely reject Passkey reauthentication-options requests for users without a Credential before creating a WebAuthn challenge.
- Display the My Page Passkey reauthentication button only after the Credential list loads successfully and contains a registered item.
- Distinguish Credential-list loading, success, and failure states according to the core data-source contract, removing the fallback that converted failures into empty lists.
- Align the release version of the plugin, Composer metadata, frontend, settings, routes, and administrator layout at 1.1.3.

### Tests

- Added regression tests for the actual service branch that blocks missing Credentials and for each list state using the core expression evaluator.

## 1.1.2

### Fixed

- Prepared the Passkey reauthentication handler and generated browser bundle for the canonical 1.1.2 patch release.
- Kept the staged deployment metadata, layout metadata, settings metadata, and read-only verifier aligned at 1.1.2 without changing authentication policy or vendor dependencies.

### Tests

- Preserved the staged WebAuthn options, assertion, verification, token, and safe diagnostic regression contracts.

## 1.1.1

### Fixed

- Passkey profile, login, and social TOTP substitution layout actions now preserve the canonical `glitter-social_totp_passkey` identifier in settings, translations, handlers, and API paths.
- Social TOTP substitution now reads Passkey policy from the canonical settings namespace.
- Passkey handlers now receive the core action context and use `G7Core.api` for authenticated WebAuthn requests.
- Passkey reauthentication now validates WebAuthn options without mutation and reports safe failures by processing stage.

### Tests

- Added regression contracts for the canonical Passkey identifier, API prefix, route shapes, and layout-generated URLs.

## 1.1.0

### Added

- Added Passkey registration, independent discoverable-credential login, social TOTP substitution, reauthentication, listing, renaming, and deletion based on `web-auth/webauthn-lib` 5.3.
- Added settings for global Passkey activation, login, registration, TOTP substitution, post-login TOTP, and user-verification policies.
- Added a dedicated table for storing Credential public keys, user handles, signature counters, backup state, registration timestamps, and last-used timestamps.

### Security

- Bind each WebAuthn challenge to the user, session, browser, purpose, and pending OAuth exchange, and consume it at most once within five minutes.
- Consume independent-login evidence atomically from the Credential row together with the core login transaction.
- Fix the RP ID and allowed Origin from the HTTPS `app.url` value without trusting the request Host header.

## 1.0.0

- Established the independent `glitter-social_totp_passkey` product lineage from the audited OAuth/TOTP baseline.
- Isolated plugin identity, namespaces, routes, settings, sessions, cache keys, logs, notifications, permissions, browser globals, layout state, DOM identifiers, and database tables.
- Preserved mandatory TOTP, recovery, transition, OAuth binding, replay prevention, and account-linking security policies.
- Added core-discovery adapters without mixed namespace declarations.
