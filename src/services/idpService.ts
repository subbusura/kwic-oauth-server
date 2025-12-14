import fs from 'fs';
import * as saml from 'samlify';
const { IdentityProvider, ServiceProvider, Constants } = saml;
import zlib from 'zlib';
import ServiceProviderModel from '../models/ServiceProvider';
import User from '../models/User';
import IdpConsent from '../models/IdpConsent';
import logger from '../lib/logger';
import { decryptSecret, encryptSecret } from '../lib/crypto';

function loadKey(path: string) {
  if (!path || !fs.existsSync(path)) {
    throw new Error('idp_key_missing');
  }
  return fs.readFileSync(path, 'utf8');
}

async function buildIdp(reqHost: string) {
  const certPath = process.env.IDP_CERTIFICATE_PATH || '';
  const keyPath = process.env.IDP_PRIVATE_KEY_PATH || '';
  const cert = loadKey(certPath);
  const key = loadKey(keyPath);
  const base = `https://${reqHost}`;

  return IdentityProvider({
    entityID: `${base}/auth/idp`,
    signingCert: cert,
    privateKey: key,
    wantAuthnRequestsSigned: false,
    singleSignOnService: [
      {
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        Location: `${base}/auth/idp/sso`,
      },
      {
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: `${base}/auth/idp/sso`,
      },
    ],
    singleLogoutService: [
      {
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        Location: `${base}/auth/idp/slo`,
      },
      {
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: `${base}/auth/idp/slo`,
      },
    ],
    nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
    messageSigningOrder: 'sign-then-encrypt',
    loginResponseTemplate: {
      context: saml.SamlLib.defaultLoginResponseTemplate.context,
    },
  });
}

async function buildSp(entityId: string) {
  const sp = await ServiceProviderModel.findOne({ entity_id: entityId });
  if (!sp) throw new Error('sp_not_found');
  return ServiceProvider({
    entityID: sp.entity_id,
    assertionConsumerService: [
      {
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: sp.acs_url,
        isDefault: true,
      },
    ],
    // Minimal settings to avoid signature/binding errors; no encryption/signature enforced
    wantAssertionsSigned: false,
    wantMessageSigned: false,
    messageSigningOrder: 'encrypt-then-sign',
    requestSignatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  });
}

export async function metadata(req: { get: (h: string) => string | undefined }) {
  const idp = await buildIdp(req.get('host') || '');
  return idp.getMetadata();
}

export async function issueResponse(options: {
  host: string;
  spEntityId: string;
  userId: string;
  relayState?: string;
  parsedRequest?: any;
}) {
  const sp = await buildSp(options.spEntityId);
  const spDoc = await ServiceProviderModel.findOne({ entity_id: options.spEntityId });
  if (!spDoc) {
    throw new Error('sp_not_found');
  }

  const user = await User.findById(options.userId);
  if (!user) throw new Error('user_not_found');
  const email = user.email || user._id.toString();



  const defaultAttrs = {
    email: email,
    name: user.profile?.name || user.profile?.displayName || '',
    givenName: user.profile?.givenName || user.profile?.firstName || '',
    surName: user.profile?.surName || user.profile?.lastName || '',
  };

  // Send both short names and URN format for maximum compatibility
  const attributes: Record<string, any> = {
    email: email,
    name: defaultAttrs.name,
    givenName: defaultAttrs.givenName,
    surName: defaultAttrs.surName,
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': email,
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': defaultAttrs.name,
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': defaultAttrs.givenName,
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': defaultAttrs.surName,
  };

  // AWS-specific attributes
  if (
    options.spEntityId === 'https://signin.aws.amazon.com/saml' &&
    user.aws_roles &&
    user.aws_roles.length > 0
  ) {
    attributes['https://aws.amazon.com/SAML/Attributes/RoleSessionName'] = email;
    attributes['https://aws.amazon.com/SAML/Attributes/Role'] = user.aws_roles.join(',');
  }

  const idp = await buildIdp(options.host);
  const idpMeta = idp.entityMeta;
  const spMeta = sp.entityMeta;

  const createTemplateCallback = (template: string) => {
    const id = idp.entitySetting.generateID();
    const assertionId = idp.entitySetting.generateID();
    const now = new Date().toISOString();
    const fiveMinutesLater = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    const base = spDoc.acs_url;
    const spEntityID = spMeta.getEntityID();

    const attributeStatements = Object.entries(attributes)
      .map(
        ([name, value]) =>
          `<saml:Attribute Name="${name}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xsi:type="xs:string">${value}</saml:AttributeValue></saml:Attribute>`
      )
      .join('');

    const tvalue: any = {
      ID: id,
      AssertionID: assertionId,
      Destination: base,
      Audience: spEntityID,
      EntityID: spEntityID,
      SubjectRecipient: base,
      Issuer: idpMeta.getEntityID(),
      IssueInstant: now,
      AssertionConsumerServiceURL: base,
      StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
      ConditionsNotBefore: now,
      ConditionsNotOnOrAfter: fiveMinutesLater,
      SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater,
      NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      NameID: email,
      InResponseTo: options.parsedRequest?.extract?.request?.id || '',
      AttributeStatement: `<saml:AttributeStatement>${attributeStatements}</saml:AttributeStatement>`,
      AuthnStatement: '',
    };

    let context = template;
    Object.entries(tvalue).forEach(([key, value]) => {
      context = context.replace(new RegExp(`\{${key}\}`, 'g'), value);
    });

    return { id, context };
  };

  const loginResponse = await idp.createLoginResponse(
    sp,
    options.parsedRequest || null,
    'post',
    { email, nameID: email, nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' },
    createTemplateCallback,
    false,
    options.relayState
  );

  let context = loginResponse.context || loginResponse;

  // If context is just base64, wrap it in HTML form
  if (typeof context === 'string' && !context.includes('<form')) {
    const escapedRelayState = options.relayState ? options.relayState.replace(/"/g, '&quot;') : '';
    context = `<!DOCTYPE html>
<html>
<head><title>Redirecting...</title></head>
<body>
<form id="saml-form" method="post" action="${spDoc.acs_url}">
<input type="hidden" name="SAMLResponse" value="${context}" />
${
  options.relayState ? `<input type="hidden" name="RelayState" value="${escapedRelayState}" />` : ''
}
<noscript><button type="submit">Continue</button></noscript>
</form>
<script>document.getElementById('saml-form').submit();</script>
</body>
</html>`;
  }

  logger.info('SAML IdP assertion issued', { sp: options.spEntityId, userId: options.userId });

  if (spDoc && spDoc.require_consent !== false) {
    await IdpConsent.updateOne(
      { user_id: options.userId, sp_entity_id: options.spEntityId },
      { $set: { granted_at: new Date() } },
      { upsert: true }
    );
  }
  return context;
}

export async function previewResponse(options: {
  host: string;
  spEntityId: string;
  userId: string;
  relayState?: string;
}) {
  const idp = await buildIdp(options.host);
  const sp = await buildSp(options.spEntityId);
  const spDoc = await ServiceProviderModel.findOne({ entity_id: options.spEntityId });
  if (!spDoc) throw new Error('sp_not_found');
  const user = await User.findById(options.userId);
  if (!user) throw new Error('user_not_found');
  const email = user.email || user._id.toString();

  const defaultAttrs = {
    email: email,
    name: user.profile?.name || user.profile?.displayName || '',
    givenName: user.profile?.givenName || user.profile?.firstName || '',
    surName: user.profile?.surName || user.profile?.lastName || '',
  };

  const attributes: Record<string, any> = {
    email: email,
    name: defaultAttrs.name,
    givenName: defaultAttrs.givenName,
    surName: defaultAttrs.surName,
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': email,
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': defaultAttrs.name,
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': defaultAttrs.givenName,
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': defaultAttrs.surName,
  };

  const userData = {
    email,
    nameID: email,
    nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  };

  const loginResponse = await idp.createLoginResponse(
    sp,
    null,
    'post',
    userData,
    undefined,
    false,
    options.relayState
  );
  const context = loginResponse.context || loginResponse;
  const samlMatch = context ? context.match(/name="SAMLResponse" value="([^"]+)"/) : null;
  const samlB64 = samlMatch ? samlMatch[1] : '';
  const samlXml = samlB64 ? Buffer.from(samlB64, 'base64').toString() : '';

  return {
    saml_response_base64: samlB64,
    saml_response_xml: samlXml,
    relay_state: options.relayState || '',
  };
}

function decodeSamlRequest(raw?: string) {
  if (!raw) return '';
  const xml = zlib.inflateRawSync(Buffer.from(raw, 'base64')).toString();
  return xml;
}

function extractIssuerFromRequest(raw?: string) {
  try {
    const xml = decodeSamlRequest(raw);
    const match =
      xml.match(/<saml:Issuer[^>]*>([^<]+)<\/saml:Issuer>/) ||
      xml.match(/<Issuer[^>]*>([^<]+)<\/Issuer>/);
    return match ? match[1] : '';
  } catch {
    return '';
  }
}

function extractRequestIdFromRequest(raw?: string) {
  try {
    const xml = decodeSamlRequest(raw);
    const match = xml.match(/ID="([^"]+)"/);
    return match ? match[1] : '';
  } catch {
    return '';
  }
}

export async function parseAuthnRequest(req: {
  query: any;
  get: (h: string) => string | undefined;
}) {
  const samlReq = req.query.SAMLRequest as string | undefined;
  const relayState = (req.query.RelayState as string) || '';
  const issuer = extractIssuerFromRequest(samlReq);
  const requestId = extractRequestIdFromRequest(samlReq);

  if (!issuer) throw new Error('invalid_authn_request');
  const sp = await ServiceProviderModel.findOne({ entity_id: issuer });
  if (!sp) throw new Error('sp_not_found');

  const idp = await buildIdp(req.get('host') || '');
  const spEntity = await buildSp(issuer);

  let parsedRequest = null;
  try {
    parsedRequest = await idp.parseLoginRequest(spEntity, 'redirect', req);
    logger.info('SAMLRequest parsed successfully', {
      hasExtract: !!parsedRequest?.extract,
      requestId: parsedRequest?.extract?.request?.id || requestId,
    });
  } catch (err) {
    logger.warn('Failed to parse SAMLRequest, using manual extraction', {
      err: (err as Error).message,
      requestId,
    });
    // Fallback: create minimal request object with extracted ID
    if (requestId) {
      parsedRequest = {
        extract: {
          request: { id: requestId },
          issuer,
        },
      };
    }
  }

  return { spEntityId: issuer, relayState, spDoc: sp, parsedRequest };
}

export function encryptMaybe(value?: string) {
  return value ? encryptSecret(value) : value;
}

export function decryptMaybe(value?: string) {
  return value ? decryptSecret(value) : value;
}
