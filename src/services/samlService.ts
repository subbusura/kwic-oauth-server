import { IdentityProvider, ServiceProvider, setSchemaValidator } from 'samlify';
import * as validator from '@authenio/samlify-node-xmllint';
import { Request } from 'express';
import SubApplication from '../models/SubApplication';
import userService from './userService';
import logger from '../lib/logger';
import { decryptSecret } from '../lib/crypto';

setSchemaValidator(validator);

function buildSp(req: Request, subAppId: string) {
  const host = req.get('host');
  const protocol = req.protocol;
  const acs = `${protocol}://${host}/auth/saml/${subAppId}/acs`;
  const entityId = `${protocol}://${host}/auth/saml/${subAppId}/metadata`;
  return new (ServiceProvider as any)({
    entityID: entityId,
    assertionConsumerService: [{ Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', Location: acs }],
    allowCreate: true
  });
}

async function buildIdp(subAppId: string) {
  const sub = await SubApplication.findById(subAppId);
  if (!sub || !sub.saml || !sub.saml.enabled) throw new Error('saml_not_enabled');
  if (!sub.saml.certificate || !sub.saml.sso_url || !sub.saml.idp_entity_id) {
    throw new Error('saml_config_incomplete');
  }
  return new (IdentityProvider as any)({
    entityID: sub.saml.idp_entity_id,
    singleSignOnService: [{ Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', Location: sub.saml.sso_url }],
    signingCert: decryptSecret(sub.saml.certificate),
    wantAuthnRequestsSigned: sub.saml.sign_request
  });
}

export async function startLogin(req: Request, subAppId: string) {
  const sp = buildSp(req, subAppId);
  const idp = await buildIdp(subAppId);
  const { context } = sp.createLoginRequest(idp, 'redirect', {
    relayState: req.query.return_to || '/'
  });
  return context; // redirect URL
}

export async function acs(req: Request, subAppId: string) {
  const sp = buildSp(req, subAppId);
  const idp = await buildIdp(subAppId);
  const { extract } = await sp.parseLoginResponse(idp, 'post', { body: req.body });
  const emailAttr = (await SubApplication.findById(subAppId))?.saml?.email_attribute || 'email';
  const email =
    extract?.attributes?.[emailAttr] ||
    extract?.attributes?.Email ||
    extract?.attributes?.email ||
    extract?.nameID;
  if (!email) {
    logger.warn('SAML assertion missing email', { subAppId });
    throw new Error('invalid_saml_assertion');
  }
  const user = await userService.findOrCreateByEmail(email);
  logger.info('SAML login success', { subAppId, userId: user.id, provider: 'saml' });
  return { user };
}

export async function metadata(req: Request, subAppId: string) {
  const sp = buildSp(req, subAppId);
  return sp.getMetadata();
}
