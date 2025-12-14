import crypto from 'crypto';

const KEY = process.env.ENCRYPTION_KEY ? Buffer.from(process.env.ENCRYPTION_KEY, 'base64') : null; // 32 bytes recommended

export function encryptSecret(value: string) {
  if (!KEY || !value) return value;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc::${Buffer.concat([iv, tag, enc]).toString('base64')}`;
}

export function decryptSecret(value?: string | null) {
  if (!value) return value || '';
  if (!value.startsWith('enc::') || !KEY) return value;
  const raw = Buffer.from(value.replace(/^enc::/, ''), 'base64');
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const data = raw.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return dec.toString('utf8');
}
