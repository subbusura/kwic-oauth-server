import express, { Router } from 'express';
import helmet from 'helmet';
import crypto from 'crypto';
import { SignJWT } from 'jose';
import userService from '../services/userService';
import { LANGUAGES, TIMEZONES, COUNTRY_CODES } from '../config/preferences';
import UserActionToken from '../models/UserActionToken';
import { hashToken } from './auth';
import Application from '../models/Application';
import User from '../models/User';

const router = Router();

const accountCsp = helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      'default-src': ["'self'"],
      'script-src': ["'self'"],
      'style-src': ["'self'"],
      'img-src': ["'self'", 'data:', 'https:'],
      'font-src': ["'self'", 'data:', 'https:'],
      'connect-src': ["'self'"],
      'form-action': ["'self'"],
      'frame-ancestors': ["'none'"]
    }
  }
});

router.use(accountCsp);

function displayName(user: any) {
  return (
    (user.profile &&
      (user.profile.name ||
        `${user.profile.givenName || ''} ${user.profile.surName || ''}`.trim())) ||
    user.email
  );
}

function getAvatarInitial(name: string) {
  return (name && name[0] ? String(name[0]) : '').toUpperCase();
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

function enforceSameUser(user: any, paramId: string, res: express.Response) {
  if (paramId !== String(user.id)) {
    res.status(403).send('forbidden');
    return false;
  }
  return true;
}

function extractPhones(body: any) {
  const codes = Array.isArray(body.phone_country_code)
    ? body.phone_country_code
    : body.phone_country_code
    ? [body.phone_country_code]
    : [];
  const numbers = Array.isArray(body.phone_number)
    ? body.phone_number
    : body.phone_number
    ? [body.phone_number]
    : [];
  const labels = Array.isArray(body.phone_label)
    ? body.phone_label
    : body.phone_label
    ? [body.phone_label]
    : [];
  const out: { label?: string; country_code?: string; number?: string }[] = [];
  for (let i = 0; i < Math.max(codes.length, numbers.length, labels.length); i += 1) {
    const number = numbers[i];
    const country_code = codes[i];
    const label = labels[i];
    if (!number) continue;
    out.push({ country_code, number, label });
  }
  return out;
}

router.get('/:userId/general', async (req, res, next) => {
  try {
    const user = await requireUser(req as any, res);
    if (!user) return;
    if (!enforceSameUser(user, req.params.userId, res)) return;

    const phones = user.phones || [];
    const name = displayName(user);
    const encodedUserId = encodeURIComponent(String(user.id));
    const phoneSummary = phones
      .map((p: any) => p?.number || '')
      .filter(Boolean)
      .join(', ');
    const appIds = (user.registered_app_ids || []).map((id: any) => String(id));
    const registeredApps = appIds.length
      ? await Application.find({ _id: { $in: appIds } }).lean()
      : [];
    const missingAppIds = appIds.filter(
      (id) => !registeredApps.some((app: any) => String(app._id) === id)
    );
    const allApps = await Application.find({}).lean();

    res.render('account/general', {
      user,
      phones,
      displayName: name,
      avatarInitial: getAvatarInitial(name),
      encodedUserId,
      phoneSummary,
      languages: LANGUAGES,
      timezones: TIMEZONES,
      countryCodes: COUNTRY_CODES,
      registeredApps,
      missingAppIds,
      allApps
    });
  } catch (err) {
    next(err);
  }
});

router.post('/:userId/general', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const user = await requireUser(req as any, res);
    if (!user) return;
    if (!enforceSameUser(user, req.params.userId, res)) return;
    const phones = extractPhones(req.body);
    await userService.updateProfile(user.id, {
      name: req.body.name,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      preferred_language: req.body.preferred_language,
      preferred_timezone: req.body.preferred_timezone,
      profile_photo_url: req.body.profile_photo_url,
      phones
    });
    res.redirect(`/accounts/${encodeURIComponent(user.id)}/general`);
  } catch (err) {
    next(err);
  }
});

router.get('/:userId/security', async (req, res, next) => {
  try {
    const user = await requireUser(req as any, res);
    if (!user) return;
    if (!enforceSameUser(user, req.params.userId, res)) return;
    const showSetPassword = user.auth_provider !== 'local' && !user.password_set;
    const name = displayName(user);
    const encodedUserId = encodeURIComponent(String(user.id));
    const rawToken = typeof req.query.pctoken === 'string' ? req.query.pctoken : '';
    let passwordChangeToken: string | null = null;
    if (rawToken && !showSetPassword) {
      const tokenDoc = await UserActionToken.findOne({
        token_hash: hashToken(rawToken),
        type: 'password_change',
        user_id: user._id,
        used_at: null,
        expires_at: { $gt: new Date() }
      });
      if (tokenDoc) passwordChangeToken = rawToken;
    }

    res.render('account/security', {
      user,
      displayName: name,
      avatarInitial: getAvatarInitial(name),
      encodedUserId,
      showSetPassword,
      passwordChangeToken,
      passwordChangeError: null
    });
  } catch (err) {
    next(err);
  }
});

router.get('/:userId/apps', async (req, res, next) => {
  try {
    const user = await requireUser(req as any, res);
    if (!user) return;
    if (!enforceSameUser(user, req.params.userId, res)) return;
    const name = displayName(user);
    const encodedUserId = encodeURIComponent(String(user.id));
    const appIds = (user.registered_app_ids || []).map((id: any) => String(id));
    const registeredApps = appIds.length
      ? await Application.find({ _id: { $in: appIds } }).lean()
      : [];
    const missingAppIds = appIds.filter(
      (id) => !registeredApps.some((app: any) => String(app._id) === id)
    );
    const allApps = await Application.find({}).lean();

    res.render('account/apps', {
      user,
      displayName: name,
      avatarInitial: getAvatarInitial(name),
      encodedUserId,
      registeredApps,
      missingAppIds,
      allApps,
      registeredIds: new Set(appIds)
    });
  } catch (err) {
    next(err);
  }
});

router.post('/:userId/password', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const user = await requireUser(req as any, res);
    if (!user) return;
    if (!enforceSameUser(user, req.params.userId, res)) return;
    const { password, password_token } = req.body;

    // If password already set, require a valid change token
    if (user.password_set) {
      if (!password_token) {
        return res.redirect(`/accounts/${encodeURIComponent(user.id)}/security`);
      }
      const tokenDoc = await UserActionToken.findOne({
        token_hash: hashToken(password_token),
        type: 'password_change',
        user_id: user._id,
        used_at: null,
        expires_at: { $gt: new Date() }
      });
      if (!tokenDoc) {
        return res.redirect(`/accounts/${encodeURIComponent(user.id)}/security`);
      }
      await userService.setPassword(user.id, password);
      tokenDoc.used_at = new Date();
      await tokenDoc.save();
      await UserActionToken.deleteMany({
        user_id: user._id,
        type: 'password_change',
        used_at: null
      });
    } else {
      await userService.setPassword(user.id, password);
    }
    res.redirect(`/accounts/${encodeURIComponent(user.id)}/security`);
  } catch (err) {
    next(err);
  }
});

router.post(
  '/:userId/password-init',
  express.urlencoded({ extended: true }),
  async (req, res, next) => {
    try {
      const user = await requireUser(req as any, res);
      if (!user) return;
      if (!enforceSameUser(user, req.params.userId, res)) return;
      const { current_password } = req.body;
      if (!current_password) {
        return res.redirect(`/accounts/${encodeURIComponent(user.id)}/security`);
      }
      try {
        await userService.verifyUser(user.email, current_password);
      } catch {
        const name = displayName(user);
        const encodedUserId = encodeURIComponent(String(user.id));
        const showSetPassword = user.auth_provider !== 'local' && !user.password_set;
        const passwordChangeToken = null;
        return res.render('account/security', {
          user,
          displayName: name,
          avatarInitial: getAvatarInitial(name),
          encodedUserId,
          showSetPassword,
          passwordChangeToken,
          passwordChangeError: 'Current password is incorrect'
        });
      }
      // create password change token
      await UserActionToken.deleteMany({ user_id: user._id, type: 'password_change' });
      const raw = crypto.randomBytes(32).toString('hex');
      const tokenHash = hashToken(raw);
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
      await UserActionToken.create({
        user_id: user._id,
        token_hash: tokenHash,
        type: 'password_change',
        expires_at: expiresAt,
        last_sent_at: new Date()
      });
      res.redirect(
        `/accounts/${encodeURIComponent(user.id)}/security?pctoken=${encodeURIComponent(raw)}`
      );
    } catch (err) {
      next(err);
    }
  }
);

router.post(
  '/:userId/secondary-email',
  express.urlencoded({ extended: true }),
  async (req, res, next) => {
    try {
      const user = await requireUser(req as any, res);
      if (!user) return;
      if (!enforceSameUser(user, req.params.userId, res)) return;
      await userService.updateSecondaryEmail(user.id, req.body.secondary_email);
      res.redirect(`/accounts/${encodeURIComponent(user.id)}/security`);
    } catch (err) {
      next(err);
    }
  }
);

router.post(
  '/:userId/apps/remove',
  express.urlencoded({ extended: true }),
  async (req, res, next) => {
    try {
      const user = await requireUser(req as any, res);
      if (!user) return;
      if (!enforceSameUser(user, req.params.userId, res)) return;
      const appId = req.body.app_id;
      if (appId) {
        await User.updateOne({ _id: user._id }, { $pull: { registered_app_ids: appId } });
      }
      res.redirect(`/accounts/${encodeURIComponent(user.id)}/apps`);
    } catch (err) {
      next(err);
    }
  }
);

router.post('/:userId/apps/add', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const user = await requireUser(req as any, res);
    if (!user) return;
    if (!enforceSameUser(user, req.params.userId, res)) return;
    const appId = req.body.app_id;
    if (!appId) return res.status(400).send('app_id required');
    await User.updateOne({ _id: user._id }, { $addToSet: { registered_app_ids: appId } });
    res.redirect(`/accounts/${encodeURIComponent(user.id)}/apps`);
  } catch (err) {
    next(err);
  }
});

router.post(
  '/:userId/apps/launch',
  express.urlencoded({ extended: true }),
  async (req, res, next) => {
    try {
      const user = await requireUser(req as any, res);
      if (!user) return;
      if (!enforceSameUser(user, req.params.userId, res)) return;
      const appId = req.body.app_id;
      if (!appId) return res.status(400).send('app_id required');
      if (
        !user.registered_app_ids ||
        !user.registered_app_ids.some((id: any) => String(id) === String(appId))
      ) {
        return res.status(403).send('Not registered for this app');
      }
      const app = await Application.findById(appId);
      if (!app || !app.origins || app.origins.length === 0) {
        return res.status(400).send('App missing launch origin');
      }
      const origin = app.launch_url || (app.origins && app.origins[0]);
      const secret = process.env.APP_LAUNCH_SECRET;
      if (!secret) {
        return res.status(500).send('Launch secret not configured');
      }
      const launchPath = app.launch_path || process.env.APP_LAUNCH_PATH || '/';
      const now = Math.floor(Date.now() / 1000);
      const jti = crypto.randomUUID();
      const token = await new SignJWT({
        sub: String(user.id),
        app: String(app._id)
      })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt(now)
        .setExpirationTime(now + 600)
        .setAudience(String(app._id))
        .setIssuer(process.env.APP_ORIGIN || 'app-launcher')
        .setJti(jti)
        .sign(Buffer.from(secret));

      let baseUrl: string | null = null;
      if (origin) {
        if (app.launch_url) {
          baseUrl = app.launch_url;
        } else {
          const normalizedOrigin = origin.replace(/\/+$/, '');
          const normalizedPath = launchPath.startsWith('/') ? launchPath : `/${launchPath}`;
          baseUrl = `${normalizedOrigin}${normalizedPath}`;
        }
      }
      if (!baseUrl) return res.status(400).send('App missing launch URL/origin');

      let url: URL;
      try {
        url = new URL(baseUrl);
      } catch {
        return res.status(400).send('Invalid launch URL');
      }
      url.searchParams.set('token', token);

      console.log(`Launching app ${app.name} for user ${user.email} to ${url.toString()}`);
      res.setHeader('Cache-Control', 'no-store');
      res.redirect(302, url.toString());
    } catch (err) {
      next(err);
    }
  }
);

export default router;
