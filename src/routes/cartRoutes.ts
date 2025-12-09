import { Router } from 'express';
import CartController from '../controllers/cartController';

const router: Router = Router();
const cartController = new CartController();

// All cart routes require authentication (handled in controller)
router.get('/', cartController.getCart);
router.post('/add', cartController.addToCart);
router.put('/:productId', cartController.updateCartItem);
router.delete('/:productId', cartController.removeFromCart);
router.delete('/', cartController.clearCart);

export default router;


