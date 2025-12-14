import { Router } from 'express';
import adminController from '../../controllers/adminController';
import { validate } from '../../lib/validator';
import authAdmin from '../../middleware/authAdmin';

const router = Router();

router.use(authAdmin);
router.get('/', adminController.listSubApplications);
router.post('/', validate.subApplication, adminController.createSubApplication);
router.put('/:id', validate.subApplicationUpdate, adminController.updateSubApplication);
router.delete('/:id', adminController.deleteSubApplication);
router.post('/:id/revoke-all', adminController.bulkRevokeForSubApplication);

export default router;
