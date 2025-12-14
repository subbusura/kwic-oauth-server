import express from 'express';
import helmet from 'helmet';
import crypto from 'crypto';
import userService from '../services/userService';
import {
  startLogin as startSamlLogin,
  acs as samlAcs,
  metadata as samlMetadata
} from '../services/samlService';
import {
  metadata as idpMetadata,
  issueResponse as issueIdpResponse,
  parseAuthnRequest,
  previewResponse as previewIdpResponse
} from '../services/idpService';
import { getGoogleAuthUrl, getGoogleUserInfo, generateState } from '../services/googleAuthService';
import IdpConsent from '../models/IdpConsent';
import ServiceProvider from '../models/ServiceProvider';
import User from '../models/User';
import SubApplication from '../models/SubApplication';
import UserActionToken from '../models/UserActionToken';
import logger from '../lib/logger';

const router = express.Router();

router.use(async (req, res, next) => {
  try {
    const subApps = await SubApplication.find({ 'saml.enabled': true }, 'saml.sso_url');
    const samlDomains = subApps
      .map((app) => {
        try {
          return app.saml?.sso_url ? new URL(app.saml.sso_url).origin : null;
        } catch {
          return null;
        }
      })
      .filter((d): d is string => d !== null);

    helmet({
      contentSecurityPolicy: {
        directives: {
          ...helmet.contentSecurityPolicy.getDefaultDirectives(),
          'default-src': ["'self'"],
          'script-src': ["'self'", "'unsafe-inline'"],
          'style-src': ["'self'", "'unsafe-inline'"],
          'img-src': ["'self'", 'data:', 'https:'],
          'font-src': ["'self'", 'data:', 'https:'],
          'connect-src': ["'self'"],
          'form-action': ["'self'", 'https://accounts.google.com', ...samlDomains],
          'frame-ancestors': ["'none'"]
        }
      }
    })(req, res, next);
  } catch (err) {
    next();
  }
});


const RESET_EXPIRY_MINUTES = 30;
const RESET_COOLDOWN_MS = 90 * 1000;
const EMAIL_RATE_LIMIT = { max: 5, windowMs: 15 * 60 * 1000 };
const IP_RATE_LIMIT = { max: 10, windowMs: 15 * 60 * 1000 };
const VERIFY_EXPIRY_MINUTES = 24 * 60;
export function hashToken(raw: string) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

const emailRequestLog = new Map<string, number[]>();
const ipRequestLog = new Map<string, number[]>();
const emailCooldowns = new Map<string, number>();
const tokenCache = new Map<
  string,
  { raw: string; expiresAt: number; type: 'password_reset' | 'email_verification' | 'password_change' }
>();

function pruneWindow(log: Map<string, number[]>, key: string, windowMs: number) {
  const now = Date.now();
  const entries = log.get(key) || [];
  const fresh = entries.filter((ts) => now - ts <= windowMs);
  log.set(key, fresh);
  return fresh;
}

function recordAndCheckRate(log: Map<string, number[]>, key: string, limit: { max: number; windowMs: number }) {
  const now = Date.now();
  const entries = pruneWindow(log, key, limit.windowMs);
  entries.push(now);
  log.set(key, entries);
  return entries.length <= limit.max;
}

function buildResetLink(req: express.Request, token: string) {
  const origin = process.env.APP_ORIGIN || `${req.protocol}://${req.get('host')}`;
  return `${origin}/auth/reset-password?token=${encodeURIComponent(token)}`;
}

function buildVerifyLink(req: express.Request, token: string) {
  const origin = process.env.APP_ORIGIN || `${req.protocol}://${req.get('host')}`;
  return `${origin}/auth/verify-email?token=${encodeURIComponent(token)}`;
}

async function sendVerificationLink(user: any, req: express.Request) {
  await UserActionToken.deleteMany({ user_id: user._id, type: 'email_verification' });
  const raw = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(raw);
  const expiresAt = new Date(Date.now() + VERIFY_EXPIRY_MINUTES * 60 * 1000);
  await UserActionToken.create({
    user_id: user._id,
    token_hash: tokenHash,
    type: 'email_verification',
    expires_at: expiresAt,
    last_sent_at: new Date()
  });
  tokenCache.set(tokenHash, { raw, expiresAt: expiresAt.getTime(), type: 'email_verification' });
  const link = buildVerifyLink(req, raw);
  logger.info('Email verification requested', { userId: user._id, email: user.email, link });
  // TODO: send email containing the verification link
}

async function loadSubApp(subAppId?: string) {
  if (!subAppId) return null;
  return SubApplication.findById(subAppId);
}

async function requireUser(req: any, res: express.Response) {
  const uid = req.cookies?.uid;
  if (!uid) {
    res.redirect(`/auth/login?return_to=${encodeURIComponent(req.originalUrl)}`);
    return null;
  }
  const user = await userService.getById(uid);
  if (!user) {
    res.clearCookie('uid');
    res.redirect(`/auth/login?return_to=${encodeURIComponent(req.originalUrl)}`);
    return null;
  }
  return user;
}

router.get('/login', async (req, res) => {
  const returnTo = String(req.query.return_to || '/');
  const subAppId = req.query.sub_app_id ? String(req.query.sub_app_id) : undefined;
  const subApp = await loadSubApp(subAppId);
  if (subApp && subApp.allow_password_login === false) {
    return res.status(403).send('Password login disabled for this sub-application');
  }
  const registerLink = `/auth/register?return_to=${encodeURIComponent(returnTo)}${
    subAppId ? `&sub_app_id=${encodeURIComponent(subAppId)}` : ''
  }`;
  const googleAllowed =
    !subApp ||
    !subApp.enabled_providers ||
    subApp.enabled_providers.length === 0 ||
    subApp.enabled_providers.includes('google');
  const googleLoginLink = `/auth/google?return_to=${encodeURIComponent(returnTo)}${
    subAppId ? `&sub_app_id=${encodeURIComponent(subAppId)}` : ''
  }`;
  res.render('auth/login', {
    returnTo,
    subAppId,
    registerLink,
    googleAllowed,
    googleLoginLink
  });
});

router.post('/login', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const { email, password, return_to, sub_app_id } = req.body;
    if (sub_app_id) {
      const subApp = await loadSubApp(sub_app_id);
      if (subApp && subApp.allow_password_login === false) {
        return res.status(403).send('Password login disabled for this sub-application');
      }
    }
    const user = await userService.verifyUser(email, password);
    res.cookie('uid', user.id, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    });
    if (!user.email_verified) {
      await sendVerificationLink(user, req);
    }
    res.redirect(return_to || '/');
  } catch (err) {
    next(err);
  }
});

router.get('/forgot', (_req, res) => {
  res.render('auth/forgot', { error: null, sent: false, email: '' });
});

router.post('/forgot', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const emailRegex = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
    if (!email || !emailRegex.test(email)) {
      return res.render('auth/forgot', {
        error: 'Please enter a valid email address.',
        sent: false,
        email
      });
    }

    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const withinEmailRate = recordAndCheckRate(emailRequestLog, email, EMAIL_RATE_LIMIT);
    const withinIpRate = recordAndCheckRate(ipRequestLog, ip, IP_RATE_LIMIT);
    const cooldownUntil = emailCooldowns.get(email) || 0;
    const now = Date.now();

    const user = await User.findOne({ email });

    // Early exit for rate limits/cooldown: generic success
    if (!withinEmailRate || !withinIpRate || now < cooldownUntil) {
      return res.render('auth/forgot', {
        error: null,
        sent: true,
        email
      });
    }

    if (user) {
      const existingToken = await UserActionToken.findOne({
        user_id: user._id,
        type: 'password_reset',
        used_at: null,
        expires_at: { $gt: new Date() }
      });

      let tokenDoc = existingToken;
      let rawToken: string | null = null;

      if (existingToken) {
        const cached = tokenCache.get(existingToken.token_hash);
        if (cached && cached.expiresAt > now) {
          rawToken = cached.raw;
        }
      }

      const sendAllowed =
        !existingToken ||
        (existingToken.last_sent_at?.getTime() || 0) + RESET_COOLDOWN_MS < now;

      if (!existingToken) {
        await UserActionToken.deleteMany({ user_id: user._id, type: 'password_reset' });
        rawToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = hashToken(rawToken);
        const expiresAt = new Date(Date.now() + RESET_EXPIRY_MINUTES * 60 * 1000);
        tokenDoc = await UserActionToken.create({
          user_id: user._id,
          token_hash: tokenHash,
          type: 'password_reset',
          expires_at: expiresAt,
          last_sent_at: new Date()
        });
        tokenCache.set(tokenHash, { raw: rawToken, expiresAt: expiresAt.getTime(), type: 'password_reset' });
      } else if (!rawToken && sendAllowed) {
        // No cached raw token (e.g., after restart). Rotate to a new token once.
        await UserActionToken.deleteMany({ user_id: user._id, type: 'password_reset' });
        rawToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = hashToken(rawToken);
        const expiresAt = new Date(Date.now() + RESET_EXPIRY_MINUTES * 60 * 1000);
        tokenDoc = await UserActionToken.create({
          user_id: user._id,
          token_hash: tokenHash,
          type: 'password_reset',
          expires_at: expiresAt,
          last_sent_at: new Date()
        });
        tokenCache.set(tokenHash, { raw: rawToken, expiresAt: expiresAt.getTime(), type: 'password_reset' });
      }

      if (sendAllowed && rawToken && tokenDoc) {
        tokenDoc.last_sent_at = new Date();
        await tokenDoc.save();
        const resetLink = buildResetLink(req, rawToken);
        logger.info('Password reset requested', { userId: user._id, email: user.email, resetLink });
        // TODO: wire actual email service with resetLink
      }
    }

    emailCooldowns.set(email, now + RESET_COOLDOWN_MS);

    return res.render('auth/forgot', {
      error: null,
      sent: true,
      email
    });
  } catch (err) {
    next(err);
  }
});

router.get('/register', async (req, res) => {
  const returnTo = String(req.query.return_to || '/');
  const subAppId = req.query.sub_app_id ? String(req.query.sub_app_id) : undefined;
  const subApp = await loadSubApp(subAppId);
  if (subApp && subApp.allow_registration === false) {
    return res.status(403).send('Registration disabled for this sub-application');
  }
  const loginLink = `/auth/login?return_to=${encodeURIComponent(returnTo)}${
    subAppId ? `&sub_app_id=${encodeURIComponent(subAppId)}` : ''
  }`;
  res.render('auth/register', { returnTo, subAppId, loginLink });
});

router.post('/register', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const { email, password, return_to, name, firstName, lastName, sub_app_id } = req.body;
    let existing = await User.findOne({ email });
    if (sub_app_id) {
      const subApp = await loadSubApp(sub_app_id);
      if (subApp && subApp.allow_registration === false) {
        return res.status(403).send('Registration disabled for this sub-application');
      }
    }
    if (existing) {
      if (sub_app_id && existing.registered_app_ids?.some((id: any) => String(id) === String(sub_app_id))) {
        return res.status(409).send('You are already registered for this application.');
      }
      // verify password matches existing account before linking sub-app
      await userService.verifyUser(email, password);
      if (sub_app_id) {
        const ids = existing.registered_app_ids || [];
        ids.push(sub_app_id as any);
        existing.registered_app_ids = ids as any;
        await existing.save();
      }
    }
    const user =
      existing ||
      (await userService.register(
        email,
        password,
        {
          name,
          givenName: firstName,
          surName: lastName
        },
        sub_app_id
      ));
    if (sub_app_id && (!user.registered_app_ids || !user.registered_app_ids.includes(sub_app_id as any))) {
      const ids = user.registered_app_ids || [];
      ids.push(sub_app_id as any);
      user.registered_app_ids = ids as any;
      await user.save();
    }
    res.cookie('uid', user.id, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    });
    await sendVerificationLink(user, req);
    res.redirect(return_to || '/');
  } catch (err) {
    next(err);
  }
});

router.post('/verify', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const uid = req.cookies?.uid;
    const returnTo = req.body.return_to || '/';
    if (!uid) return res.redirect(`/auth/login?return_to=${encodeURIComponent(returnTo)}`);
    const user = await User.findById(uid);
    if (!user) return res.redirect(`/auth/login?return_to=${encodeURIComponent(returnTo)}`);
    if (!user.email_verified) {
      await sendVerificationLink(user, req);
    }
    res.redirect(returnTo);
  } catch (err) {
    next(err);
  }
});

router.get('/reset-password', async (req, res) => {
  const token = String(req.query.token || '');
  if (!token) {
    return res.render('auth/resetPassword', { token: '', invalid: true, error: null });
  }
  const tokenHash = hashToken(token);
  const tokenDoc = await UserActionToken.findOne({
    token_hash: tokenHash,
    type: 'password_reset',
    expires_at: { $gt: new Date() },
    used_at: null
  });
  if (!tokenDoc) {
    return res.render('auth/resetPassword', { token: '', invalid: true, error: null });
  }
  return res.render('auth/resetPassword', { token, invalid: false, error: null });
});

router.post('/reset-password', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const token = String(req.body.token || '');
    const password = String(req.body.password || '');
    const confirmPassword = String(req.body.confirmPassword || '');
    if (!token) {
      return res.render('auth/resetPassword', { token: '', invalid: true, error: null });
    }
    if (password.length < 8) {
      return res.render('auth/resetPassword', {
        token,
        invalid: false,
        error: 'Password must be at least 8 characters long.'
      });
    }
    if (password !== confirmPassword) {
      return res.render('auth/resetPassword', {
        token,
        invalid: false,
        error: 'Passwords do not match.'
      });
    }
    const tokenHash = hashToken(token);
    const tokenDoc = await UserActionToken.findOne({
      token_hash: tokenHash,
      type: 'password_reset',
      expires_at: { $gt: new Date() },
      used_at: null
    });
    if (!tokenDoc) {
      return res.render('auth/resetPassword', { token: '', invalid: true, error: null });
    }
    const user = await User.findById(tokenDoc.user_id);
    if (!user) {
      return res.render('auth/resetPassword', { token: '', invalid: true, error: null });
    }
    await userService.setPassword(user.id, password);
    tokenDoc.used_at = new Date();
    await tokenDoc.save();
    await UserActionToken.deleteMany({ user_id: user._id, type: 'password_reset', used_at: null });
    res.clearCookie('uid');
    return res.render('auth/resetSuccess');
  } catch (err) {
    next(err);
  }
});

router.get('/verify-email', async (req, res, next) => {
  try {
    const token = String(req.query.token || '');
    if (!token) return res.status(400).send('Invalid or expired link');
    const tokenHash = hashToken(token);
    const tokenDoc = await UserActionToken.findOne({
      token_hash: tokenHash,
      type: 'email_verification',
      expires_at: { $gt: new Date() },
      used_at: null
    });
    if (!tokenDoc) return res.status(400).send('Invalid or expired link');

    const user = await User.findById(tokenDoc.user_id);
    if (!user) return res.status(400).send('Invalid or expired link');

    user.email_verified = true;
    await user.save();
    tokenDoc.used_at = new Date();
    await tokenDoc.save();
    await UserActionToken.deleteMany({ user_id: user._id, type: 'email_verification', used_at: null });

    return res.send('Email verified. You can close this window.');
  } catch (err) {
    next(err);
  }
});

router.get('/logout', (req, res) => {
  res.clearCookie('uid');
  res.redirect('/auth/login');
});

router.get('/auth/profile', (req, res) => {
  const uid = req.cookies?.uid;
  const target = uid ? `/accounts/${encodeURIComponent(uid)}/general` : '/auth/login';
  res.redirect(target);
});

router.get('/accounts', async (req, res) => {
  const uid = req.cookies?.uid;
  if (!uid) {
    return res.redirect(`/auth/login?return_to=${encodeURIComponent('/accounts')}`);
  }
  return res.redirect(`/accounts/${encodeURIComponent(uid)}/general`);
});

function displayName(user: any) {
  return (
    (user.profile &&
      (user.profile.name ||
        `${user.profile.givenName || ''} ${user.profile.surName || ''}`.trim())) ||
    user.email
  );
}

function enforceSameUser(user: any, paramId: string, res: express.Response) {
  if (paramId !== String(user.id)) {
    res.status(403).send('forbidden');
    return false;
  }
  return true;
}

router.get('/consent', (req, res) => {
  const returnTo = String(req.query.return_to || '/oauth/authorize');
  const scope = String(req.query.scope || '');
  const clientId = String(req.query.client_id || '');
  const scopesList = scope.split(' ').filter(Boolean);
  res.render('auth/consent', {
    returnTo,
    scope,
    clientId,
    scopesList
  });
});

router.post('/consent', express.urlencoded({ extended: true }), (req, res) => {
  const { client_id, return_to } = req.body;
  if (client_id) {
    res.cookie(`consent_${client_id}`, 'true', {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    });
  }
  res.redirect(return_to || '/oauth/authorize');
});

// SAML start (Cloudflare or other IdP per sub-app)
router.get('/saml/:subAppId/start', async (req, res, next) => {
  try {
    const redirectUrl = await startSamlLogin(req, req.params.subAppId);
    res.redirect(302, redirectUrl);
  } catch (err) {
    next(err);
  }
});

// SAML ACS
router.post(
  '/saml/:subAppId/acs',
  express.urlencoded({ extended: true }),
  async (req, res, next) => {
    try {
      const { user } = await samlAcs(req, req.params.subAppId);
      res.cookie('uid', user.id, {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production'
      });
      const returnTo = req.body.RelayState || '/';
      res.redirect(returnTo);
    } catch (err) {
      next(err);
    }
  }
);

// SAML metadata
router.get('/saml/:subAppId/metadata', async (req, res, next) => {
  try {
    const xml = await samlMetadata(req, req.params.subAppId);
    res.type('application/xml').send(xml);
  } catch (err) {
    next(err);
  }
});

// IdP metadata (for external SPs to consume this server as IdP)
router.get('/idp/metadata', async (req, res, next) => {
  try {
    const xml = await idpMetadata(req);
    res.type('application/xml').send(xml);
  } catch (err) {
    next(err);
  }
});

// IdP SSO endpoint (supports AuthnRequest via Redirect binding or sp_entity_id param) and requires logged-in user
router.get('/idp/sso', async (req, res, next) => {
  try {
    let spEntityId = '';
    let relayState = String(req.query.relay_state || '');
    let spDoc: any;
    let parsedRequest: any = null;

    let samlRequest = req.query.SAMLRequest as string | undefined;

    if (samlRequest) {
      const parsed = await parseAuthnRequest(req);
      spEntityId = parsed.spEntityId;
      relayState = parsed.relayState;
      spDoc = parsed.spDoc;
      parsedRequest = parsed.parsedRequest;
    } else {
      spEntityId = String(req.query.sp_entity_id || '');
      spDoc = await ServiceProvider.findOne({ entity_id: spEntityId });

      // Check if SAMLRequest was stored in cookie (from consent flow)
      const cookieName = `saml_req_${Buffer.from(spEntityId)
        .toString('base64')
        .replace(/[^a-zA-Z0-9]/g, '_')}`;
      const storedSamlReq = req.cookies?.[cookieName];
      if (storedSamlReq) {
        const mockReq = {
          query: { SAMLRequest: storedSamlReq, RelayState: relayState },
          get: req.get.bind(req)
        };
        const parsed = await parseAuthnRequest(mockReq);
        parsedRequest = parsed.parsedRequest;
        res.clearCookie(cookieName);
      }
    }
    if (!spEntityId || !spDoc) {
      return res.status(400).send('Missing or unknown sp_entity_id');
    }
    const userId = req.cookies?.uid;
    if (!userId || !(await User.findById(userId))) {
      const returnTo = encodeURIComponent(req.originalUrl);
      return res.redirect(`/auth/login?return_to=${returnTo}`);
    }
    if (spDoc.require_consent !== false) {
      const consent = await IdpConsent.findOne({ user_id: userId, sp_entity_id: spEntityId });
      if (!consent) {
        // Store SAMLRequest in cookie to preserve it through consent flow
        if (req.query.SAMLRequest) {
          const cookieName = `saml_req_${Buffer.from(spEntityId)
            .toString('base64')
            .replace(/[^a-zA-Z0-9]/g, '_')}`;
          res.cookie(cookieName, req.query.SAMLRequest, {
            httpOnly: true,
            maxAge: 5 * 60 * 1000, // 5 minutes
            sameSite: 'lax'
          });
        }
        const returnTo = encodeURIComponent(
          `/auth/idp/sso?${
            req.url.split('?')[1] || `sp_entity_id=${encodeURIComponent(spEntityId)}`
          }`
        );
        return res.redirect(
          `/auth/idp/consent?sp_entity_id=${encodeURIComponent(
            spEntityId
          )}&relay_state=${encodeURIComponent(relayState)}&return_to=${returnTo}`
        );
      }
    }
    const html = await issueIdpResponse({
      host: req.get('host') || '',
      spEntityId,
      userId,
      relayState,
      parsedRequest
    });
    res.type('text/html').send(html);
  } catch (err) {
    next(err);
  }
});

// IdP SLO endpoint (minimal)
router.get('/idp/slo', (req, res) => {
  res.clearCookie('uid');
  res.status(200).send('Logged out');
});

// IdP consent prompt
router.get('/idp/consent', async (req, res, next) => {
  try {
    const spEntityId = String(req.query.sp_entity_id || '');
    const relayState = String(req.query.relay_state || '');
    const returnTo = String(req.query.return_to || '');
    const userId = req.cookies?.uid;
    const sp = await ServiceProvider.findOne({ entity_id: spEntityId });
    if (!sp) return res.status(400).send('Unknown service provider');
    if (!userId || !(await User.findById(userId))) {
      const back = encodeURIComponent(req.originalUrl);
      return res.redirect(`/auth/login?return_to=${back}`);
    }
    const attrs = sp.attributes || [];
    res.render('auth/idpConsent', {
      sp,
      attrs,
      spEntityId,
      relayState,
      returnTo
    });
  } catch (err) {
    next(err);
  }
});

router.post('/idp/consent', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const spEntityId = req.body.sp_entity_id;
    const relayState = req.body.relay_state;
    const returnTo = req.body.return_to || '/';
    const userId = req.cookies?.uid;
    if (!userId) {
      const back = encodeURIComponent(req.originalUrl);
      return res.redirect(`/auth/login?return_to=${back}`);
    }
    await IdpConsent.updateOne(
      { user_id: userId, sp_entity_id: spEntityId },
      { $set: { granted_at: new Date() } },
      { upsert: true }
    );
    const ssoUrl = `/auth/idp/sso?sp_entity_id=${encodeURIComponent(
      spEntityId
    )}&relay_state=${encodeURIComponent(relayState)}`;
    return res.redirect(ssoUrl);
  } catch (err) {
    next(err);
  }
});

// Google OAuth
router.get('/google', (req, res) => {
  const returnTo = String(req.query.return_to || '/');
  const state = generateState();
  res.cookie('google_oauth_state', state, {
    httpOnly: true,
    maxAge: 10 * 60 * 1000,
    sameSite: 'lax'
  });
  res.cookie('google_oauth_return', returnTo, {
    httpOnly: true,
    maxAge: 10 * 60 * 1000,
    sameSite: 'lax'
  });
  res.redirect(getGoogleAuthUrl(state));
});

router.get('/google/callback', async (req, res, next) => {
  try {
    const { code, state } = req.query;
    const savedState = req.cookies?.google_oauth_state;
    const returnTo = req.cookies?.google_oauth_return || '/';

    if (!state || state !== savedState) {
      return res.status(400).send('Invalid state');
    }

    const googleUser = await getGoogleUserInfo(code as string);
    const user = await userService.findOrCreateGoogleUser({
      email: googleUser.email,
      googleId: googleUser.googleId,
      name: googleUser.name,
      givenName: googleUser.givenName,
      familyName: googleUser.familyName,
      picture: googleUser.picture
    });

    res.cookie('uid', user.id, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    });
    res.clearCookie('google_oauth_state');
    res.clearCookie('google_oauth_return');
    res.redirect(returnTo);
  } catch (err) {
    next(err);
  }
});

// IdP preview (admin token required)
router.get('/idp/preview', async (req, res, next) => {
  try {
    const spEntityId = String(req.query.sp_entity_id || '');
    const userId = String(req.query.user_id || req.cookies?.uid || '');
    const relayState = req.query.relay_state as string | undefined;
    if (!spEntityId || !userId) {
      return res.status(400).json({ error: 'sp_entity_id and user_id are required' });
    }
    const preview = await previewIdpResponse({
      host: req.get('host') || '',
      spEntityId,
      userId,
      relayState
    });
    res.json(preview);
  } catch (err) {
    next(err);
  }
});

export default router;
