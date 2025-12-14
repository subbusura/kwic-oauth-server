# OAuth Server Starter (Express + TypeScript)

Fully wired starter for OAuth2/OIDC with MongoDB, Redis, BullMQ webhooks, and admin APIs.

## Stack

- Node.js + Express + TypeScript
- oidc-provider for OAuth2/OIDC (Auth Code + PKCE, Client Credentials, Refresh)
- MongoDB (Mongoose) for apps/clients/users/tokens/webhooks
- Redis for sessions, blacklists, BullMQ queue
- Jest, ESLint, Prettier, Husky
- Docker + docker-compose for local dev

## Quickstart

```bash
npm ci
npm run dev
```

Or with Docker:

```bash
docker-compose up --build
```

## Environment

See `.env.example` values:

```
NODE_ENV=development
PORT=4000
MONGO_URI=mongodb://mongo:27017/oauth
REDIS_URL=redis://redis:6379
JWT_KID=auth-key-1
JWKS_PRIVATE_KEY_PATH=./secrets/jwks_private.pem
JWKS_PUBLIC_KEY_PATH=./secrets/jwks_public.pem
OIDC_ISSUER=http://localhost:4000
ACCESS_TOKEN_EXP=900
REFRESH_TOKEN_EXP=1209600
REFRESH_ROTATION=true
ADMIN_SECRET_TOKEN=replace-me
SECRETS_MANAGER_PROVIDER=local
```

## Key commands

- `npm run dev` – dev server with ts-node-dev
- `npm test` – Jest unit tests
- `npm run lint` – ESLint
- `npm run build` – TypeScript build

## Structure

See `src/` for app, routes, services, middleware; `workers/` for BullMQ worker; `docs/openapi.yaml` for API skeleton; `tests/` for Jest examples.

## Admin UI

Placeholder Next.js-ready folder at `admin-ui/` that references the provided images:

- `file:///mnt/data/8c9b9ecf-367e-4cfe-bade-150085448600.png`
- `file:///mnt/data/4eadbff2-e88a-49cb-a224-fb87aba30a8a.png`

## Security notes

- Do not commit secrets. Provide JWKS keys via mounted secrets.
- Access token revocation uses Redis blacklist (`revoked:jti:<jti>`).
- Refresh tokens are hashed and rotated.

## CI

`.github/workflows/ci.yml` runs lint, tests, and build.

/oauth/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:3000/callback&scope=read

http://localhost:4000/auth/register?return_to=/oauth/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:4000/callback&scope=read

/auth/register?return_to=%2Foauth%2Fauthorize%3Fresponse_type%3Dcode%26client_id%3Ddemo-client%26redirect_uri%3Dhttp%253A%252F%252Flocalhost%253A4000%252Fcallback%26scope%3Dread

/auth/login?return_to=%2Foauth%2Fauthorize%3Fresponse_type%3Dcode%26client_id%3Ddemo-client%26redirect_uri%3Dhttp%253A%252F%252Flocalhost%253A4000%252Fcallback%26scope%3Dread

curl -X POST http://localhost:4000/admin/clients \
 -H "x-admin-token: askdlasjkdl" \
 -H "Content-Type: application/json" \
 -d '{
"sub_application_id":"692489d77f761dae8a44d21d",
"client_id":"demo-client",
"grant_types":["authorization_code","refresh_token","client_credentials"],
"redirect_uris":["http://localhost:4000/callback"],
"scopes":["read","write"],
"client_type":"confidential"
}'

curl -X POST http://localhost:4000/admin/sub-applications \
 -H "x-admin-token: askdlasjkdl" \
 -H "Content-Type: application/json" \
 -d '{"application_id":"692489d77f761dae8a44d21d","name":"Demo SubApp","redirect_uris":["http://localhost:3000/callback"]}'

curl -X POST http://localhost:4000/admin/clients \
 -H "x-admin-token: askdlasjkdl" \
 -H "Content-Type: application/json" \
 -d '{
"sub_application_id": "692489d77f761dae8a44d21d",
"client_id": "demo-client",
"client_type": "confidential",
"grant_types": ["authorization_code", "refresh_token", "client_credentials"],
"redirect_uris": ["http://localhost:4000/callback"],
"scopes": ["read","write"]
}'

curl -X POST http://localhost:4000/oauth/token \
 -H "Content-Type: application/json" \
 -d '{
"grant_type":"authorization_code",
"code":"OG_oU2kvs8ucxdmc-TT_TR8mty8_Re2K",
"client_id":"demo-client",
"client_secret":"6f33e2b9c14ceda6203b9a7567b0c32f24277ba77bcd9722",
"redirect_uri":"http://localhost:4000/callback",
"scope":"read"
}'

$2a$12$N1Yjv8F88YP/KAqdnhok4.VsoUXdRY2kdvFaENOpfY5TZblNScivW

{"authorization_code":"3SJtGBsj-vnhtc4bp7MpiP4KuB7w6Lnr"}
