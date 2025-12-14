import { body, query, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';

function handleValidation(req: Request, res: Response, next: NextFunction) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
}

export const validate = {
  authorize: [
    query('response_type').equals('code'),
    query('client_id').isString(),
    query('redirect_uri').isString(),
    query('code_challenge').optional().isString(),
    query('code_challenge_method').optional().isString(),
    handleValidation
  ],
  token: [
    body('grant_type').isString(),
    body('code').optional().isString(),
    body('refresh_token').optional().isString(),
    body('client_id').optional().isString(),
    body('client_secret').optional().isString(),
    handleValidation
  ],
  revoke: [body('token').isString(), body('token_type_hint').optional().isString(), handleValidation],
  introspect: [body('token').isString(), handleValidation],
  application: [body('name').isString(), handleValidation],
  applicationUpdate: [body('name').optional().isString(), handleValidation],
  subApplication: [body('name').isString(), body('application_id').isString(), handleValidation],
  subApplicationUpdate: [body('name').optional().isString(), handleValidation],
  client: [body('sub_application_id').isString(), body('client_id').isString(), handleValidation],
  clientUpdate: [body('status').optional().isString(), handleValidation],
  webhook: [body('sub_application_id').isString(), body('callback_url').isURL(), handleValidation],
  webhookUpdate: [body('callback_url').optional().isURL(), handleValidation]
};
