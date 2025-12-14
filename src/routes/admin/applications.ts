import { Router } from 'express';
import adminController from '../../controllers/adminController';
import { validate } from '../../lib/validator';
import authAdmin from '../../middleware/authAdmin';

const router = Router();

router.use(authAdmin);
router.get('/', adminController.listApplications);
router.post('/', validate.application, adminController.createApplication);
router.put('/:id', validate.applicationUpdate, adminController.updateApplication);
router.delete('/:id', adminController.deleteApplication);

export default router;
