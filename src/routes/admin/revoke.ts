import { Router } from 'express';
import adminController from '../../controllers/adminController';
import authAdmin from '../../middleware/authAdmin';

const router = Router();

router.use(authAdmin);
router.post('/bulk', adminController.bulkRevoke);

export default router;
