import { Request } from 'express';
import { nanoid } from 'nanoid';
import { SignJWT, generateKeyPair, exportJWK, JWK } from 'jose';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import Token from '../models/Token';
import OAuthClient from '../models/OAuthClient';
import { redis, config } from '../config';
import logger from '../lib/logger';

let jwkCache: { publicJwk: JWK; privateKey: CryptoKey } | null = null;

async function loadKeys() {
  if (!jwkCache) {
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    jwkCache = { publicJwk: await exportJWK(publicKey), privateKey: privateKey as CryptoKey };
    jwkCache.publicJwk.kid = process.env.JWT_KID || 'auth-key-1';
  }
  return jwkCache;
}

async function validateClient(
  clientId: string,
  clientSecret: string | undefined,
  grantType: string,
  redirectUri?: string,
  requireSecret = true
) {
  const client = await OAuthClient.findOne({ client_id: clientId, status: 'active' });
  if (!client) throw new Error('invalid_client');
  if (client.grant_types && !client.grant_types.includes(grantType)) {
    logger.warn('Unauthorized grant for client', { client_id: clientId, grantType });
    throw new Error('unauthorized_client');
  }
  if (client.client_type === 'confidential' && requireSecret) {
    if (!clientSecret) throw new Error('invalid_client');
    const validSecret = await bcrypt.compare(clientSecret, client.client_secret_enc);
    if (!validSecret) throw new Error('invalid_client');
  }
  if (redirectUri && client.redirect_uris && !client.redirect_uris.includes(redirectUri)) {
    logger.warn('Redirect URI mismatch', { client_id: clientId, redirectUri });
    throw new Error('invalid_grant');
  }
  return client;
}

async function authorize(req: Request, userId: string) {
  const clientId = String(req.query.client_id || '');
  const redirectUri = String(req.query.redirect_uri || '');
  const scope = String(req.query.scope || '');
  await validateClient(clientId, undefined, 'authorization_code', redirectUri, false);
  const code = nanoid(32);
  const payload = { userId, clientId, scope, subApplicationId: undefined as any, redirectUri };
  const client = await OAuthClient.findOne({ client_id: clientId });
  if (client) payload.subApplicationId = client.sub_application_id;
  await redis.setex(`code:${code}`, 300, JSON.stringify(payload));
  logger.info('Authorization code issued', { client_id: clientId, userId, sub_application_id: payload.subApplicationId });
  return { authorization_code: code };
}

function hashRefreshToken(token: string) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function issueAccessToken(payload: {
  clientId: string;
  userId?: string;
  subApplicationId?: string;
  scope?: string;
}) {
  const { privateKey } = await loadKeys();
  const now = Math.floor(Date.now() / 1000);
  const exp = now + config.accessTokenExp;
  const jti = nanoid();
  const jwt = await new SignJWT({ sub_app_id: payload.subApplicationId, scopes: payload.scope })
    .setProtectedHeader({ alg: 'RS256', kid: process.env.JWT_KID || 'auth-key-1' })
    .setIssuedAt()
    .setIssuer(config.issuer)
    .setAudience(payload.clientId)
    .setJti(jti)
    .setExpirationTime(exp)
    .sign(privateKey);

  await Token.create({
    client_id: payload.clientId,
    user_id: payload.userId,
    sub_application_id: payload.subApplicationId,
    scope: payload.scope ? String(payload.scope).split(' ').filter(Boolean) : [],
    jti,
    token_type: 'access',
    access_token_hash: '',
    refresh_token_hash: '',
    issued_at: new Date(),
    expires_at: new Date(exp * 1000)
  });

  return {
    token_type: 'Bearer',
    access_token: jwt,
    expires_in: config.accessTokenExp,
    scope: payload.scope
  };
}

async function issueRefreshToken(payload: {
  clientId: string;
  userId?: string;
  subApplicationId?: string;
  scope?: string;
}) {
  const refreshToken = nanoid(48);
  const refreshHash = hashRefreshToken(refreshToken);
  const now = Date.now();
  const exp = new Date(now + config.refreshTokenExp * 1000);
  const jti = nanoid();

  await Token.create({
    client_id: payload.clientId,
    user_id: payload.userId,
    sub_application_id: payload.subApplicationId,
    scope: payload.scope ? String(payload.scope).split(' ').filter(Boolean) : [],
    jti,
    token_type: 'refresh',
    access_token_hash: '',
    refresh_token_hash: refreshHash,
    issued_at: new Date(now),
    expires_at: exp
  });

  return { refresh_token: refreshToken, refresh_expires_in: config.refreshTokenExp, refresh_jti: jti };
}

async function token(req: Request) {
  const grantType = req.body.grant_type;
  if (!['authorization_code', 'client_credentials', 'refresh_token'].includes(grantType)) {
    throw new Error('unsupported_grant_type');
  }

  const client = await validateClient(
    req.body.client_id,
    req.body.client_secret,
    grantType,
    req.body.redirect_uri
  );

  if (grantType === 'authorization_code') {
    const data = await redis.get(`code:${req.body.code}`);
    if (!data) throw new Error('invalid_grant');
    await redis.del(`code:${req.body.code}`);
    const parsed = JSON.parse(data);
    if (parsed.redirectUri && parsed.redirectUri !== req.body.redirect_uri) {
      throw new Error('invalid_grant');
    }
    logger.info('Token exchange via authorization_code', { client_id: parsed.clientId, userId: parsed.userId });
    const access = await issueAccessToken({
      clientId: parsed.clientId,
      userId: parsed.userId,
      subApplicationId: parsed.subApplicationId,
      scope: parsed.scope
    });
    const refresh = await issueRefreshToken({
      clientId: parsed.clientId,
      userId: parsed.userId,
      subApplicationId: parsed.subApplicationId,
      scope: parsed.scope
    });
    return { ...access, ...refresh };
  }

  if (grantType === 'client_credentials') {
    logger.info('Token issued via client_credentials', { client_id: client.client_id });
    return issueAccessToken({
      clientId: client.client_id,
      subApplicationId: String(client.sub_application_id),
      scope: req.body.scope
    });
  }

  if (grantType === 'refresh_token') {
    const incoming = req.body.refresh_token;
    if (!incoming) throw new Error('invalid_grant');
    const refreshHash = hashRefreshToken(incoming);
    const stored = await Token.findOne({
      token_type: 'refresh',
      client_id: client.client_id,
      refresh_token_hash: refreshHash,
      revoked: false,
      expires_at: { $gt: new Date() }
    });
    if (!stored) throw new Error('invalid_grant');

    stored.revoked = true;
    await stored.save();
    logger.info('Refresh token rotated', { client_id: stored.client_id, refresh_jti: stored.jti });

    const access = await issueAccessToken({
      clientId: stored.client_id || client.client_id,
      userId: stored.user_id?.toString(),
      subApplicationId: stored.sub_application_id?.toString(),
      scope: stored.scope?.join(' ')
    });
    const refresh = await issueRefreshToken({
      clientId: stored.client_id || client.client_id,
      userId: stored.user_id?.toString(),
      subApplicationId: stored.sub_application_id?.toString(),
      scope: stored.scope?.join(' ')
    });
    return { ...access, ...refresh };
  }
}

async function revoke(req: Request) {
  const token = req.body.token as string;
  if (!token) return;
  const jti = req.body.jti || token;
  const ttl = config.accessTokenExp;
  await redis.setex(`revoked:jti:${jti}`, ttl, '1');
  await Token.updateMany({ jti }, { revoked: true });
}

async function introspect(req: Request) {
  const jti = req.body.token;
  const revoked = await redis.get(`revoked:jti:${jti}`);
  return { active: !revoked, jti };
}

async function jwks() {
  const { publicJwk } = await loadKeys();
  return { keys: [publicJwk] };
}

export default { authorize, token, revoke, introspect, jwks };
