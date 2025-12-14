import mongoose from 'mongoose';
import Redis from 'ioredis';

const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
export const redis = new Redis(redisUrl);

export function connectDatastores() {
  const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/oauth';
  if (mongoose.connection.readyState === 0) {
    mongoose.connect(mongoUri);
  }
}

export const config = {
  issuer: process.env.OIDC_ISSUER || 'http://localhost:4000',
  accessTokenExp: Number(process.env.ACCESS_TOKEN_EXP || 900),
  refreshTokenExp: Number(process.env.REFRESH_TOKEN_EXP || 1209600),
  refreshRotation: process.env.REFRESH_ROTATION !== 'false'
};
