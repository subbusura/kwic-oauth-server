# Feature Overview (for quick reference / LLM context)

## Core Auth
- OAuth2/OIDC endpoints: `/oauth/authorize`, `/oauth/token` (authorization_code, client_credentials, refresh_token), `/oauth/revoke`, `/oauth/introspect`, `/oauth/jwks.json`.
- Tokens: JWT access tokens (short-lived), opaque refresh tokens (hashed in Mongo, rotated), revocation via Mongo + Redis blacklist (`revoked:jti:<jti>`).
- PKCE (recommended for public clients), exact redirect URI matching, client grant-type enforcement.

## Models (Mongo, snake_case)
- `applications`, `sub_applications`, `oauth_clients`, `users`, `tokens`, `webhooks`, `service_providers`, `idp_consents`.
- `SubApplication`: redirect_uris, SAML config, login/registration toggles, enabled_providers.
- `ServiceProvider`: entity_id, acs_url, cert, attribute mappings, consent flag, metadata_xml.

## Admin UI / Admin API
- `/admin-ui`: login via env creds; manage Applications, Sub-Applications (incl. SAML + login/registration toggles + enabled_providers), Clients (plaintext secret shown once), Webhooks, Service Providers (for IdP mode, accepts metadata XML).
- Admin API: `/admin/*` with `x-admin-token` (CRUD for apps/sub-apps/clients/webhooks, bulk revoke).

## Login/Registration UI
- Styled pages with animated backgrounds (login/register/consent).
- Sub-application-aware: `sub_app_id` controls allow_registration, allow_password_login, enabled_providers (e.g., Google button visibility).
- Consent page styled; error handling with hidden fields preserved.

## SAML (SP role per sub-app)
- Config on SubApplication: `saml.enabled`, `idp_entity_id`, `sso_url`, `certificate`, `sign_request`, `email_attribute`.
- Endpoints: `/auth/saml/:subAppId/start`, `/auth/saml/:subAppId/acs`, `/auth/saml/:subAppId/metadata`.
- IdP assertions map email/name/profile.* to user; sets `uid` cookie and continues auth.

## SAML (IdP role for external SPs)
- Metadata: `/auth/idp/metadata` (entityID `https://<host>/auth/idp`, SSO Redirect+POST, SLO Redirect+POST, NameID emailAddress).
- SSO: `/auth/idp/sso` supports AuthnRequest Redirect binding; consent per SP if enabled.
- SP registry: Service Providers stored via Admin UI or API (supports metadata XML import).
- Assertion issuance: minimal unsigned by default; attributes map email/name/profile.*; consent recorded in `idp_consents`.
- Preview: `/auth/idp/preview` returns SAMLResponse (base64 + XML) for debugging (admin token required).

## OAuth Clients
- Clients stored hashed secret; secret returned once on creation. Grant types, redirect URIs, scopes, client_type, sub_app linkage.

## Logging / Error Handling
- Winston logger (`LOG_LEVEL` env); levels: error, warn, info, audit, debug.
- Global error handler logs path/message/stack; no secrets logged.

## Webhooks
- Model: callback_url, secret_enc, event_type, sub_application_id.
- Worker: BullMQ queue `webhookDelivery`, HMAC signing, backoff/retries; dispatchDirect helper.

## Tests
- Jest unit tests (e.g., `tests/unit/idp.spec.ts` for IdP flow) with mocks; extend as needed.

## Env / Keys
- OAuth: `JWKS_PRIVATE_KEY_PATH`, `JWKS_PUBLIC_KEY_PATH`, `JWT_KID`, token expirations.
- Datastores: `MONGO_URI`, `REDIS_URL`.
- IdP: `IDP_PRIVATE_KEY_PATH`, `IDP_CERTIFICATE_PATH` (self-signed generator `scripts/generate_idp_certs.sh`), optional `ENCRYPTION_KEY` for secrets.
- Admin: `ADMIN_SECRET_TOKEN`, `ADMIN_UI_USERNAME`, `ADMIN_UI_PASSWORD`.
- Logging: `LOG_LEVEL`.

## Scripts
- `scripts/generate_keys.sh` (JWKS), `scripts/generate_idp_certs.sh` (IdP certs).

## CI / Tooling
- ESLint/Prettier, Jest config, Dockerfile, docker-compose, GitHub Actions CI.

## Notable Endpoints
- OAuth: `/oauth/*`, `/oauth/jwks.json`, `/authorize`, `/oauth/token`, `/oauth/revoke`, `/oauth/introspect`.
- Auth UI: `/auth/login`, `/auth/register`, `/auth/consent`.
- SAML SP: `/auth/saml/:subAppId/start|acs|metadata`.
- SAML IdP: `/auth/idp/metadata`, `/auth/idp/sso`, `/auth/idp/slo` (minimal), `/auth/idp/preview`.
- Admin UI: `/admin-ui/*`; Admin API: `/admin/*`.

## Current defaults/assumptions
- SAML IdP responses currently unsigned/minimal to avoid binding/signature issues; enable signing if required by SP.
- AuthnRequest signature validation skipped unless a cert is provided; verify per-SP if needed.
- Tokens, secrets, and certs should be mounted via env/secret files; do not commit secrets.

## Profile / Security
- Profile pages `/accounts/:userId/general` (cookie `uid` required) with photo URL, first/last name, preferred language, timezone, multiple phones (country_code + number + label).
- Security page `/accounts/:userId/security` shows email verification flag, secondary email update, set/change password (only required when account came from social login), 2FA/devices placeholders to wire to future providers.
- Data stored on `users` collection: secondary_email, email_verified, phones[], preferred_language, timezone, profile_photo_url, password_set flag.
