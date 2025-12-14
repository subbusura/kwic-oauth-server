import express from 'express';
import helmet from 'helmet';
import { signHMAC } from '../lib/hmac';
import Application from '../models/Application';
import SubApplication from '../models/SubApplication';
import OAuthClient from '../models/OAuthClient';
import clientService from '../services/clientService';
import ServiceProvider from '../models/ServiceProvider';
import { encryptSecret } from '../lib/crypto';
import logger from '../lib/logger';

const router = express.Router();

const adminCsp = helmet({
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
router.use(adminCsp);

const ADMIN_USER = process.env.ADMIN_UI_USERNAME || 'admin';
const ADMIN_PASS = process.env.ADMIN_UI_PASSWORD || 'changeme';
const ADMIN_SECRET = process.env.ADMIN_SECRET_TOKEN || 'admin-secret';

function parseSpMetadata(xml: string) {
  const entityMatch = xml.match(/entityID="([^"]+)"/i);
  const acsMatch = xml.match(/AssertionConsumerService[^>]+Location="([^"]+)"/i);
  const certMatch = xml.match(/<X509Certificate>([^<]+)<\/X509Certificate>/i);
  if (!entityMatch || !acsMatch) {
    throw new Error('metadata_missing_entity_or_acs');
  }
  return {
    entity_id: entityMatch[1],
    acs_url: acsMatch[1],
    certificate: certMatch ? certMatch[1] : ''
  };
}

function computeSession() {
  return signHMAC(ADMIN_SECRET, `${ADMIN_USER}:${ADMIN_PASS}`);
}

function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  const cookie = req.cookies?.admin_ui_session;
  if (cookie && cookie === computeSession()) {
    return next();
  }
  return res.redirect('/admin-ui/login');
}

router.get('/login', (_req, res) => {
  res.render('admin/login');
});

router.post('/login', express.urlencoded({ extended: true }), (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    res.cookie('admin_ui_session', computeSession(), {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    });
    return res.redirect('/admin-ui');
  }
  return res.status(401).send('Invalid credentials');
});

router.use(requireAdmin);

router.get('/', async (_req, res) => {
  const apps = await Application.find().lean();
  const subs = await SubApplication.find().lean();
  const clients = await OAuthClient.find().lean();
  const serviceProviders = await ServiceProvider.find().lean();
  res.render('admin/dashboard', { apps, subs, clients, serviceProviders });
});

router.post('/applications', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const origins = req.body.origins ? String(req.body.origins).split(',').map((o) => o.trim()) : [];
    await Application.create({
      name: req.body.name,
      description: req.body.description,
      origins
    });
    res.redirect('/admin-ui');
  } catch (err) {
    next(err);
  }
});

router.post('/applications/:id/delete', async (req, res, next) => {
  try {
    await Application.findByIdAndDelete(req.params.id);
    res.redirect('/admin-ui');
  } catch (err) {
    next(err);
  }
});

router.post('/applications/update', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const origins = req.body.origins ? String(req.body.origins).split(',').map((o) => o.trim()) : undefined;
    await Application.findByIdAndUpdate(
      req.body.id,
      {
        ...(req.body.name ? { name: req.body.name } : {}),
        ...(req.body.description ? { description: req.body.description } : {}),
        ...(origins ? { origins } : {})
      },
      { new: true }
    );
    res.redirect('/admin-ui');
  } catch (err) {
    next(err);
  }
});

router.post('/sub-applications', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const redirect_uris = req.body.redirect_uris
      ? String(req.body.redirect_uris)
          .split(',')
          .map((u) => u.trim())
      : [];
    await SubApplication.create({
      application_id: req.body.application_id,
      name: req.body.name,
      redirect_uris,
      allow_registration: req.body.allow_registration !== undefined,
      allow_password_login: req.body.allow_password_login !== undefined,
      enabled_providers: req.body.enabled_providers
        ? String(req.body.enabled_providers)
            .split(',')
            .map((p) => p.trim())
        : []
    });
    res.redirect('/admin-ui');
  } catch (err) {
    next(err);
  }
});

router.post('/sub-applications/:id/delete', async (req, res, next) => {
  try {
    await SubApplication.findByIdAndDelete(req.params.id);
    res.redirect('/admin-ui');
  } catch (err) {
    next(err);
  }
});

router.post('/sub-applications/update', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const redirect_uris = req.body.redirect_uris
      ? String(req.body.redirect_uris)
          .split(',')
          .map((u) => u.trim())
      : undefined;
    const providers = req.body.enabled_providers
      ? String(req.body.enabled_providers)
          .split(',')
          .map((p) => p.trim())
      : undefined;
    const samlUpdate: any = {};
    if (req.body.saml_enabled !== undefined) samlUpdate.enabled = !!req.body.saml_enabled;
    if (req.body.saml_idp_entity_id) samlUpdate.idp_entity_id = req.body.saml_idp_entity_id;
    if (req.body.saml_sso_url) samlUpdate.sso_url = req.body.saml_sso_url;
    if (req.body.saml_certificate) samlUpdate.certificate = encryptSecret(req.body.saml_certificate);
    if (req.body.saml_sign_request !== undefined) samlUpdate.sign_request = !!req.body.saml_sign_request;
    if (req.body.saml_email_attribute) samlUpdate.email_attribute = req.body.saml_email_attribute;
    const setObj: any = {
      ...(req.body.name ? { name: req.body.name } : {}),
      ...(redirect_uris ? { redirect_uris } : {}),
      ...(req.body.allow_registration !== undefined ? { allow_registration: !!req.body.allow_registration } : {}),
      ...(req.body.allow_password_login !== undefined
        ? { allow_password_login: !!req.body.allow_password_login }
        : {}),
      ...(providers ? { enabled_providers: providers } : {})
    };
    if (Object.keys(samlUpdate).length > 0) {
      setObj.saml = { ...samlUpdate };
    }
    await SubApplication.findByIdAndUpdate(req.body.id, setObj, { new: true });
    res.redirect('/admin-ui');
  } catch (err) {
    next(err);
  }
});

router.post('/clients', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const grant_types = req.body.grant_types
      ? String(req.body.grant_types)
          .split(',')
          .map((g) => g.trim())
      : [];
    const redirect_uris = req.body.redirect_uris
      ? String(req.body.redirect_uris)
          .split(',')
          .map((u) => u.trim())
      : [];
    const scopes = req.body.scopes
      ? String(req.body.scopes)
          .split(',')
          .map((s) => s.trim())
      : [];
    const created = await clientService.createClient({
      sub_application_id: req.body.sub_application_id,
      client_id: req.body.client_id,
      client_type: req.body.client_type || 'confidential',
      grant_types,
      redirect_uris,
      scopes,
      status: 'active'
    });
    res.render('admin/clientCreated', { client: created });
  } catch (err) {
    next(err);
  }
});

router.post('/clients/:id/delete', async (req, res, next) => {
  try {
    await OAuthClient.findByIdAndDelete(req.params.id);
    res.redirect('/admin-ui');
  } catch (err) {
    next(err);
  }
});

router.post('/clients/update', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const grant_types = req.body.grant_types
      ? String(req.body.grant_types)
          .split(',')
          .map((g) => g.trim())
      : undefined;
    const redirect_uris = req.body.redirect_uris
      ? String(req.body.redirect_uris)
          .split(',')
          .map((u) => u.trim())
      : undefined;
    const scopes = req.body.scopes
      ? String(req.body.scopes)
          .split(',')
          .map((s) => s.trim())
      : undefined;
    await OAuthClient.findByIdAndUpdate(
      req.body.id,
      {
        ...(grant_types ? { grant_types } : {}),
        ...(redirect_uris ? { redirect_uris } : {}),
        ...(scopes ? { scopes } : {}),
        ...(req.body.status ? { status: req.body.status } : {})
      },
      { new: true }
    );
    res.redirect('/admin-ui');
  } catch (err) {
    next(err);
  }
});

// Service Providers (IdP mode)
router.post('/service-providers', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    let parsedMeta: any;
    if (req.body.metadata_xml) {
      try {
        parsedMeta = parseSpMetadata(req.body.metadata_xml.replace(/\r?\n/g, ''));
      } catch (err) {
        logger.warn('Failed to parse SP metadata', { err: (err as Error).message });
        return res.status(400).send('Invalid metadata XML');
      }
    }
    const attrInput = (req.body.attributes || '').trim();
    const attributes =
      attrInput.length > 0
        ? attrInput
            .split(',')
            .map((pair: string) => pair.trim())
            .filter(Boolean)
            .map((pair: string) => {
              const [name, source] = pair.split('=');
              return { name: name?.trim(), source: (source || name)?.trim() };
            })
            .filter((a: any) => a.name)
        : undefined;
    const entityId = parsedMeta?.entity_id || (req.body.entity_id || '').trim();
    const acsUrl = parsedMeta?.acs_url || (req.body.acs_url || '').trim();
    if (!entityId || !acsUrl) {
      return res.status(400).send('Entity ID and ACS URL are required (metadata or manual).');
    }
    await ServiceProvider.create({
      name: req.body.name,
      entity_id: entityId,
      acs_url: acsUrl,
      certificate: encryptSecret(parsedMeta?.certificate || req.body.certificate || ''),
      metadata_xml: req.body.metadata_xml || '',
      sign_assertion: req.body.sign_assertion !== undefined,
      sign_response: req.body.sign_response !== undefined,
      require_consent: req.body.require_consent !== undefined,
      attributes
    });
    res.redirect('/admin-ui');
  } catch (err) {
    next(err);
  }
});

router.post('/service-providers/:id/delete', async (req, res, next) => {
  try {
    await ServiceProvider.findByIdAndDelete(req.params.id);
    res.redirect('/admin-ui');
  } catch (err) {
    next(err);
  }
});

export default router;
