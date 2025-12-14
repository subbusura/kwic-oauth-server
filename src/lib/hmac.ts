import crypto from 'crypto';

export function signHMAC(secret: string, body: string) {
  return crypto.createHmac('sha256', secret).update(body).digest('hex');
}

export function verifyHMAC(secret: string, body: string, sig: string) {
  const expected = signHMAC(secret, body);
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
}
