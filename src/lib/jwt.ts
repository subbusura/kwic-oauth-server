import { JWTPayload, SignJWT } from 'jose';

export async function signJwt(payload: JWTPayload, key: CryptoKey, kid: string, issuer: string, audience?: string) {
  const jwt = new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuedAt()
    .setIssuer(issuer);
  if (audience) jwt.setAudience(audience);
  if (payload.exp) jwt.setExpirationTime(payload.exp);
  if (payload.jti) jwt.setJti(payload.jti);
  return jwt.sign(key);
}
