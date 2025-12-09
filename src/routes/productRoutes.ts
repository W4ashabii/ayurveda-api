import { Router } from 'express';
import ProductController from '../controllers/productController';
import { adminAuth } from '../middleware/adminAuth';

const router: Router = Router();
const productController = new ProductController();

// Public routes
router.get('/', productController.getAllProducts);
router.get('/:id', productController.getProductById);

// Admin routes
router.post('/', adminAuth, productController.createProduct);
router.put('/:id', adminAuth, productController.updateProduct);
router.delete('/:id', adminAuth, productController.deleteProduct);

export default router;
