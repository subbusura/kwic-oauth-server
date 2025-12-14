import { Request, Response, NextFunction } from 'express';
import oauthService from '../services/oauthService';

async function authorize(req: Request, res: Response, next: NextFunction) {
  try {
    const userId = req.cookies?.uid;
    const returnTo = encodeURIComponent(req.originalUrl);
    if (!userId) {
      return res.redirect(`/auth/login?return_to=${returnTo}`);
    }
    const consentCookieName = req.query.client_id ? `consent_${req.query.client_id}` : '';
    if (req.query.client_id && !req.cookies?.[consentCookieName]) {
      const consentUrl = `/auth/consent?return_to=${returnTo}&client_id=${req.query.client_id}&scope=${
        req.query.scope || ''
      }`;
      return res.redirect(consentUrl);
    }

    const result = await oauthService.authorize(req, userId);
    res.status(200).json(result);
  } catch (err) {
    next(err);
  }
}

async function token(req: Request, res: Response, next: NextFunction) {
  try {
    const result = await oauthService.token(req);
    res.status(200).json(result);
  } catch (err) {
    next(err);
  }
}

async function revoke(req: Request, res: Response, next: NextFunction) {
  try {
    await oauthService.revoke(req);
    res.status(200).json({ revoked: true });
  } catch (err) {
    next(err);
  }
}

async function introspect(req: Request, res: Response, next: NextFunction) {
  try {
    const result = await oauthService.introspect(req);
    res.status(200).json(result);
  } catch (err) {
    next(err);
  }
}

async function jwks(_req: Request, res: Response, next: NextFunction) {
  try {
    const keys = await oauthService.jwks();
    res.status(200).json(keys);
  } catch (err) {
    next(err);
  }
}

export default { authorize, token, revoke, introspect, jwks };
