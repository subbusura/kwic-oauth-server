import { Router } from 'express';
import adminController from '../../controllers/adminController';
import { validate } from '../../lib/validator';
import authAdmin from '../../middleware/authAdmin';

const router = Router();

router.use(authAdmin);
router.get('/', adminController.listClients);
router.post('/', validate.client, adminController.createClient);
router.put('/:id', validate.clientUpdate, adminController.updateClient);
router.delete('/:id', adminController.deleteClient);

export default router;
