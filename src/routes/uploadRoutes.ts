import { Router } from 'express';
import UploadController from '../controllers/uploadController';
import { adminAuth } from '../middleware/adminAuth';
import { upload } from '../middleware/upload';

const router: Router = Router();
const uploadController = new UploadController();

// Admin route for image upload
router.post('/image', adminAuth, upload.single('image'), uploadController.uploadImage);

export default router;

