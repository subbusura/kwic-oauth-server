# Developer Guide & API Usage

## Security & Coding Practices
- Client auth: confidential clients must send `client_secret` on token/refresh; validate `grant_type` and `redirect_uri` against registered values and client grant_types.
- PKCE: enforce `code_challenge` / `code_verifier` for public clients.
- Tokens: short-lived access; refresh tokens are opaque, SHA-256 hashed, rotated on use; add `revoked:jti:<jti>` to Redis and set `revoked=true` in Mongo when revoking.
- Redirect URI: exact match only (no wildcards) unless explicitly allowed and documented.
- Secrets: JWKS via mounted secrets; never commit secrets; bcrypt (12+) for passwords; do not log tokens/assertions/secrets.
- Validation & rate limits: `express-validator` on all inputs; rate-limit `/oauth`, `/admin`, and SAML endpoints; SameSite+HttpOnly cookies; CSRF via state/RelayState.
- Logging: `src/lib/logger.ts` with levels `error,warn,info,audit,debug`; mask sensitive data.
- Webhooks: HMAC signing, exponential backoff (BullMQ), idempotency recommended.
- SAML: per sub-application config (`saml.enabled`, `idp_entity_id`, `sso_url`, `certificate`, `sign_request`, `email_attribute`); exact ACS/redirect match; validate RelayState; do not log assertions.

## Admin APIs (protected by `x-admin-token` or `Authorization: Bearer <ADMIN_SECRET_TOKEN>`)
Base URL: `http://localhost:4000/admin`

Applications
```
GET  /applications
POST /applications
PUT  /applications/:id
DEL  /applications/:id
```
Example:
```
curl -X POST http://localhost:4000/admin/applications \
  -H "x-admin-token: $ADMIN_SECRET_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Demo App","description":"Example","origins":["http://localhost:3000"]}'
```

Sub-Applications
```
GET  /sub-applications
POST /sub-applications
PUT  /sub-applications/:id
DEL  /sub-applications/:id
POST /sub-applications/:id/revoke-all
```
Example:
```
curl -X POST http://localhost:4000/admin/sub-applications \
  -H "x-admin-token: $ADMIN_SECRET_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"application_id":"<appId>","name":"Demo SubApp","redirect_uris":["http://localhost:3000/callback"]}'
```

Clients
```
GET  /clients
POST /clients
PUT  /clients/:id
DEL  /clients/:id
```
Example (confidential):
```
curl -X POST http://localhost:4000/admin/clients \
  -H "x-admin-token: $ADMIN_SECRET_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "sub_application_id":"<subAppId>",
    "client_id":"demo-client",
    "grant_types":["authorization_code","refresh_token","client_credentials"],
    "redirect_uris":["http://localhost:3000/callback"],
    "scopes":["read","write"],
    "client_type":"confidential"
  }'
```

Webhooks
```
GET  /webhooks
POST /webhooks
PUT  /webhooks/:id
DEL  /webhooks/:id
```

Bulk Revoke
```
POST /revoke/bulk   # body can include client_id/user_id/sub_application_id filters
```

## OAuth/OIDC Client Flows
Base URL: `http://localhost:4000`

1) Authorization Code (with login/consent)
- Direct user to `/auth/login?return_to=<urlencoded /oauth/authorize...>` or `/auth/register?...`
- Example return_to payload (URL-encode it):
  `/oauth/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:3000/callback&scope=read`
- On success you get `{ authorization_code: <code> }`.

2) Token Exchange (authorization_code)
```
curl -X POST http://localhost:4000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type":"authorization_code",
    "code":"<code>",
    "client_id":"demo-client",
    "client_secret":"<client-secret>",
    "redirect_uri":"http://localhost:3000/callback",
    "scope":"read"
  }'
```
Response: `access_token`, `token_type`, `expires_in`, `scope`, plus `refresh_token` (rotated on use).

3) Client Credentials
```
curl -X POST http://localhost:4000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type":"client_credentials",
    "client_id":"demo-client",
    "client_secret":"<client-secret>",
    "scope":"read"
  }'
```

4) Refresh Token
```
curl -X POST http://localhost:4000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type":"refresh_token",
    "refresh_token":"<refresh>",
    "client_id":"demo-client",
    "client_secret":"<client-secret>"
  }'
```

5) Introspect (stubbed: checks revocation flag)
```
curl -X POST http://localhost:4000/oauth/introspect \
  -H "Content-Type: application/json" \
  -d '{"token":"<jti-or-token>"}'
```

6) Revoke (RFC 7009 style)
```
curl -X POST http://localhost:4000/oauth/revoke \
  -H "Content-Type: application/json" \
  -d '{"token":"<access-or-refresh>","token_type_hint":"access_token"}'
```

## Data Model Notes (snake_case)
- Clients: `oauth_clients` with `client_id`, `client_secret_enc`, `grant_types`, `redirect_uris`, `client_type`, `sub_application_id`.
- Tokens: `tokens` with `token_type` (`access`|`refresh`), `scope`, `jti`, `client_id`, `user_id`, `sub_application_id`, `access_token_hash`, `refresh_token_hash`, `revoked`, `issued_at`, `expires_at`.
- Users/Admins: password hashes stored in `password_hash`.
- Webhooks: `webhooks` with `secret_enc`, `callback_url`, `event_type`, `sub_application_id`.

## Operational Checks
- JWKS: `/oauth/jwks.json` serves public keys for JWT verification.
- Redis keys: `code:<auth_code>` (5m TTL), `revoked:jti:<jti>` for blacklist.
- Queue: BullMQ queue `webhookDelivery`; worker at `src/workers/webhookWorker.ts`.

## Per sub-application SAML (Cloudflare or other SAML 2.0 IdPs)
- Configure on each SubApplication: `saml.enabled`, `idp_entity_id`, `sso_url`, `certificate`, `sign_request`, `email_attribute`.
- Start URL: `/auth/saml/<subAppId>/start?return_to=/oauth/authorize?...`
- ACS: `/auth/saml/<subAppId>/acs` (HTTP POST from IdP) sets `uid` cookie then redirects via RelayState.
- Email mapping: uses `email_attribute` (default `email`) or falls back to `Email`/`email`/`nameID`.

## Admin UI (HTML)
- `/admin-ui/login` (env creds: `ADMIN_UI_USERNAME` / `ADMIN_UI_PASSWORD`)
- Dashboard: list/create/update/delete Applications, Sub-Applications, Clients; update SAML settings per Sub-Application; on client creation it displays plaintext `client_secret` once.

## IdP (this server acting as IdP for external SPs)
- IdP metadata: `/auth/idp/metadata` (entityID `https://<host>/auth/idp`, SSO POST+Redirect, SLO POST+Redirect, NameIDFormat emailAddress; WantAuthnRequestsSigned=true; uses keys at `IDP_PRIVATE_KEY_PATH` and `IDP_CERTIFICATE_PATH`).
- IdP SSO (Redirect binding):
  - With AuthnRequest: `/auth/idp/sso?SAMLRequest=...&RelayState=...` (requires logged-in user via `uid` cookie).
  - Or parameterized: `/auth/idp/sso?sp_entity_id=<entityId>&relay_state=<state>`.
- IdP SLO (minimal): `/auth/idp/slo` clears the session cookie.
- SP registry: `service_providers` collection with `entity_id`, `acs_url`, optional `certificate`, and attribute mappings.
- Admin UI: create/delete Service Providers and set sign_assertion/sign_response and attribute mappings.

## Recommended dev flow
1) `npm ci && npm run dev`
2) Create Application → Sub-Application → Client (Admin UI or Admin API).
3) User flow: `/auth/login?return_to=<encoded /oauth/authorize...>` → consent → get `authorization_code`.
4) Exchange code at `/oauth/token` with `client_id`, **plaintext** `client_secret`, matching `redirect_uri`.
5) Optional SAML: configure SubApplication.saml, then `/auth/saml/<subAppId>/start`.
6) Webhooks: configure via admin; run worker `node dist/workers/webhookWorker.js`.
7) IdP mode: set IdP keys, register Service Providers in Admin UI, give SPs `/auth/idp/metadata`, and have them initiate AuthnRequest to `/auth/idp/sso`. Consent prompts can appear if enabled per SP.

## Cloudflare Workers/Pages migration notes
- Config: see `cloudflare/wrangler.toml` (bindings for D1, KV namespaces for auth codes/revocations/sessions/JWKS cache, and Queue for webhooks). Set `OIDC_ISSUER` to the public domain.
- Entry: `cloudflare/functions/[[path]].ts` is a Pages Functions stub; replace Express routing with Workers handlers for `/oauth`, `/auth`, `/admin`, and IdP endpoints.
- Data: `cloudflare/migrations/0001_init.sql` mirrors Mongo collections; apply via `wrangler d1 migrations apply`. Store short-lived items in KV (auth codes, revocation flags, sessions).
- Crypto: load JWT private key via `wrangler secret put JWT_PRIVATE_KEY` and `JWT_KID`. Replace `bcryptjs` with WebCrypto hashing; use `fetch` instead of `axios`.
- Queues: `cloudflare/queues/worker.ts` is a stub consumer for webhook delivery; enqueue from the main worker via `env.WEBHOOK_QUEUE.send`.
- SAML: `samlify`/fs/zlib are not Workers-compatible; swap to a Workers-safe SAML implementation or hosted IdP helper. Store IdP cert/key in secrets or R2.
- OAuth + IdP + basic Auth Worker implemented in `cloudflare/functions/[[path]].ts`: supports `/oauth/authorize`, `/oauth/token`, `/oauth/introspect`, `/oauth/revoke`, `/oauth/jwks.json`, `/auth/idp/metadata`, `/auth/idp/sso`, `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/me`, `/auth/accounts/:id/general`, `/auth/accounts/:id/security`, `/auth/consent`, `/health`. HTML forms for login/register/account/consent are included; JSON APIs remain. Sessions are stored in KV (`sid` cookie, 7d TTL). Uses D1 for tokens/clients/ServiceProviders/users and KV for auth codes/revocations/sessions. Admin panel and webhooks remain omitted. IdP SAML response is unsigned/minimal; add signing if required.
- Consent: `/oauth/authorize` now enforces consent cookie (`consent_<client_id>`). If missing, it redirects to `/auth/consent` with `return_to`, `client_id`, and `scope` preserved.
