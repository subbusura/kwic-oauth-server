import { Router } from 'express';
import applications from './applications';
import subapps from './subapps';
import clients from './clients';
import webhooks from './webhooks';
import revoke from './revoke';

const router = Router();

router.use('/applications', applications);
router.use('/sub-applications', subapps);
router.use('/clients', clients);
router.use('/webhooks', webhooks);
router.use('/revoke', revoke);

export default router;
