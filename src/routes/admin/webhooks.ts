import { Router } from 'express';
import adminController from '../../controllers/adminController';
import { validate } from '../../lib/validator';
import authAdmin from '../../middleware/authAdmin';

const router = Router();

router.use(authAdmin);
router.get('/', adminController.listWebhooks);
router.post('/', validate.webhook, adminController.createWebhook);
router.put('/:id', validate.webhookUpdate, adminController.updateWebhook);
router.delete('/:id', adminController.deleteWebhook);

export default router;
