import { Router } from 'express';
import { validate } from '../lib/validator';
import oauthController from '../controllers/oauthController';

const router = Router();

router.get('/authorize', validate.authorize, oauthController.authorize);
router.post('/token', validate.token, oauthController.token);
router.post('/revoke', validate.revoke, oauthController.revoke);
router.post('/introspect', validate.introspect, oauthController.introspect);
router.get('/jwks.json', oauthController.jwks);

export default router;
