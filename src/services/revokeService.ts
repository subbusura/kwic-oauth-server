import Token from '../models/Token';
import { redis, config } from '../config';
import logger from '../lib/logger';

async function normalizeFilter(raw: any) {
  const filter: any = { ...raw };
  if (filter.subApplicationId) {
    filter.sub_application_id = filter.subApplicationId;
    delete filter.subApplicationId;
  }
  if (filter.clientId) {
    filter.client_id = filter.clientId;
    delete filter.clientId;
  }
  if (filter.userId) {
    filter.user_id = filter.userId;
    delete filter.userId;
  }
  return filter;
}

async function bulkRevoke(rawFilter: any) {
  const filter = await normalizeFilter(rawFilter);
  const tokens = await Token.find(filter);
  const ttl = config.accessTokenExp;
  for (const token of tokens) {
    if (token.jti) {
      await redis.setex(`revoked:jti:${token.jti}`, ttl, '1');
    }
    token.revoked = true;
    await token.save();
  }
  if (tokens.length > 0) {
    logger.audit('Bulk revoke executed', { filter, count: tokens.length });
  }
  return { revoked: tokens.length };
}

export default { bulkRevoke };
