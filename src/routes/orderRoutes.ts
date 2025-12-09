import { Router } from 'express';
import OrderController from '../controllers/orderController';
import { adminAuth } from '../middleware/adminAuth';

const router: Router = Router();
const orderController = new OrderController();

// Public routes
router.post('/', orderController.createOrder);
router.get('/:id', orderController.getOrderById);

// Admin routes
router.get('/', adminAuth, orderController.getAllOrders);
router.put('/:id', adminAuth, orderController.updateOrder);
router.delete('/:id', adminAuth, orderController.deleteOrder);

export default router;
