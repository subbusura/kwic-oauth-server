import mongoose from 'mongoose';
import Redis from 'ioredis';
import fs from 'fs';

const envCache = new Map<string, string>();

function getEnv(key: string, defaultValue?: string): string {
  if (envCache.has(key)) {
    return envCache.get(key)!;
  }

  const fileKey = `${key}_FILE`;
  let value: string | undefined;

  if (process.env[fileKey]) {
    try {
      value = fs.readFileSync(process.env[fileKey], 'utf8').trim();
    } catch (err) {
      console.error(`Failed to read secret file ${process.env[fileKey]}:`, err);
      if (defaultValue === undefined) {
        throw new Error(`Required secret ${fileKey} could not be read`);
      }
    }
  }

  if (value === undefined) {
    value = process.env[key] || defaultValue;
  }

  if (value === undefined) {
    throw new Error(`Required environment variable ${key} is not set`);
  }

  envCache.set(key, value);
  return value;
}

const redisUrl = getEnv('REDIS_URL', 'redis://localhost:6379');
export const redis = new Redis(redisUrl);

export function connectDatastores() {
  const mongoUri = getEnv('MONGO_URI', 'mongodb://localhost:27017/oauth');
  if (mongoose.connection.readyState === 0) {
    mongoose.connect(mongoUri);
  }
}

export const config = {
  issuer: getEnv('OIDC_ISSUER', 'http://localhost:4000'),
  accessTokenExp: Number(getEnv('ACCESS_TOKEN_EXP', '900')),
  refreshTokenExp: Number(getEnv('REFRESH_TOKEN_EXP', '1209600')),
  refreshRotation: getEnv('REFRESH_ROTATION', 'true') !== 'false',
  adminSecretToken: getEnv('ADMIN_SECRET_TOKEN'),
  appLaunchSecret: getEnv('APP_LAUNCH_SECRET')
};
