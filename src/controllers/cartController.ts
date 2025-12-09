import { Request, Response } from 'express';
import Cart from '../models/Cart';
import { verifyJwt, JwtUser } from '../config/passport';
import { createSuccessResponse, createErrorResponse } from '../utils';
import { HTTP_STATUS, API_MESSAGES } from '../constant';

interface AuthRequest extends Request {
  user?: JwtUser;
}

class CartController {
  // Get user's cart
  getCart = async (req: Request, res: Response): Promise<void> => {
    try {
      const token = req.cookies?.auth_token || req.headers.authorization?.replace('Bearer ', '');
      
      if (!token) {
        const { response, statusCode } = createErrorResponse(
          'User not authenticated',
          HTTP_STATUS.UNAUTHORIZED
        );
        res.status(statusCode).json(response);
        return;
      }

      const user = verifyJwt(token);
      if (!user || !user.email) {
        const { response, statusCode } = createErrorResponse(
          'Invalid token',
          HTTP_STATUS.UNAUTHORIZED
        );
        res.status(statusCode).json(response);
        return;
      }

      let cart = await Cart.findOne({ 'user.email': user.email });
      
      if (!cart) {
        // Create empty cart if it doesn't exist
        cart = new Cart({
          user: {
            email: user.email,
            name: user.name,
          },
          items: [],
        });
        await cart.save();
      }

      // Populate product details if needed
      await cart.populate('items.product', 'name image price stock');
      
      const { response, statusCode } = createSuccessResponse(
        cart,
        'Cart retrieved successfully'
      );
      res.status(statusCode).json(response);
    } catch (error) {
      console.error('Error fetching cart:', error);
      const { response, statusCode } = createErrorResponse('Internal server error');
      res.status(statusCode).json(response);
    }
  };

  // Add item to cart
  addToCart = async (req: Request, res: Response): Promise<void> => {
    try {
      const token = req.cookies?.auth_token || req.headers.authorization?.replace('Bearer ', '');
      
      if (!token) {
        const { response, statusCode } = createErrorResponse(
          'User not authenticated',
          HTTP_STATUS.UNAUTHORIZED
        );
        res.status(statusCode).json(response);
        return;
      }

      const user = verifyJwt(token);
      if (!user || !user.email) {
        const { response, statusCode } = createErrorResponse(
          'Invalid token',
          HTTP_STATUS.UNAUTHORIZED
        );
        res.status(statusCode).json(response);
        return;
      }

      const { product, name, image, price, quantity } = req.body;

      if (!product || !name || !image || price === undefined || !quantity) {
        const { response, statusCode } = createErrorResponse(
          'Missing required fields',
          HTTP_STATUS.BAD_REQUEST
        );
        res.status(statusCode).json(response);
        return;
      }

      let cart = await Cart.findOne({ 'user.email': user.email });

      if (!cart) {
        cart = new Cart({
          user: {
            email: user.email,
            name: user.name,
          },
          items: [],
        });
      }

      // Check if item already exists in cart
      const existingItemIndex = cart.items.findIndex(
        (item) => item.product.toString() === product
      );

      if (existingItemIndex >= 0) {
        // Update quantity if item exists
        cart.items[existingItemIndex].quantity += quantity;
      } else {
        // Add new item
        cart.items.push({
          product,
          name,
          image,
          price,
          quantity,
        });
      }

      await cart.save();

      const { response, statusCode } = createSuccessResponse(
        cart,
        'Item added to cart successfully'
      );
      res.status(statusCode).json(response);
    } catch (error: any) {
      console.error('Error adding to cart:', error);
      const { response, statusCode } = createErrorResponse(
        error.message || 'Failed to add item to cart',
        HTTP_STATUS.BAD_REQUEST
      );
      res.status(statusCode).json(response);
    }
  };

  // Update item quantity
  updateCartItem = async (req: Request, res: Response): Promise<void> => {
    try {
      const token = req.cookies?.auth_token || req.headers.authorization?.replace('Bearer ', '');
      
      if (!token) {
        const { response, statusCode } = createErrorResponse(
          'User not authenticated',
          HTTP_STATUS.UNAUTHORIZED
        );
        res.status(statusCode).json(response);
        return;
      }

      const user = verifyJwt(token);
      if (!user || !user.email) {
        const { response, statusCode } = createErrorResponse(
          'Invalid token',
          HTTP_STATUS.UNAUTHORIZED
        );
        res.status(statusCode).json(response);
        return;
      }

      const { productId } = req.params;
      const { quantity } = req.body;

      if (quantity === undefined || quantity < 0) {
        const { response, statusCode } = createErrorResponse(
          'Invalid quantity',
          HTTP_STATUS.BAD_REQUEST
        );
        res.status(statusCode).json(response);
        return;
      }

      const cart = await Cart.findOne({ 'user.email': user.email });

      if (!cart) {
        const { response, statusCode } = createErrorResponse(
          'Cart not found',
          HTTP_STATUS.NOT_FOUND
        );
        res.status(statusCode).json(response);
        return;
      }

      if (quantity === 0) {
        // Remove item if quantity is 0
        cart.items = cart.items.filter(
          (item) => item.product.toString() !== productId
        );
      } else {
        // Update quantity
        const itemIndex = cart.items.findIndex(
          (item) => item.product.toString() === productId
        );

        if (itemIndex >= 0) {
          cart.items[itemIndex].quantity = quantity;
        } else {
          const { response, statusCode } = createErrorResponse(
            'Item not found in cart',
            HTTP_STATUS.NOT_FOUND
          );
          res.status(statusCode).json(response);
          return;
        }
      }

      await cart.save();

      const { response, statusCode } = createSuccessResponse(
        cart,
        'Cart updated successfully'
      );
      res.status(statusCode).json(response);
    } catch (error: any) {
      console.error('Error updating cart:', error);
      const { response, statusCode } = createErrorResponse(
        error.message || 'Failed to update cart',
        HTTP_STATUS.BAD_REQUEST
      );
      res.status(statusCode).json(response);
    }
  };

  // Remove item from cart
  removeFromCart = async (req: Request, res: Response): Promise<void> => {
    try {
      const token = req.cookies?.auth_token || req.headers.authorization?.replace('Bearer ', '');
      
      if (!token) {
        const { response, statusCode } = createErrorResponse(
          'User not authenticated',
          HTTP_STATUS.UNAUTHORIZED
        );
        res.status(statusCode).json(response);
        return;
      }

      const user = verifyJwt(token);
      if (!user || !user.email) {
        const { response, statusCode } = createErrorResponse(
          'Invalid token',
          HTTP_STATUS.UNAUTHORIZED
        );
        res.status(statusCode).json(response);
        return;
      }

      const { productId } = req.params;

      const cart = await Cart.findOne({ 'user.email': user.email });

      if (!cart) {
        const { response, statusCode } = createErrorResponse(
          'Cart not found',
          HTTP_STATUS.NOT_FOUND
        );
        res.status(statusCode).json(response);
        return;
      }

      cart.items = cart.items.filter(
        (item) => item.product.toString() !== productId
      );

      await cart.save();

      const { response, statusCode } = createSuccessResponse(
        cart,
        'Item removed from cart successfully'
      );
      res.status(statusCode).json(response);
    } catch (error: any) {
      console.error('Error removing from cart:', error);
      const { response, statusCode } = createErrorResponse(
        error.message || 'Failed to remove item from cart',
        HTTP_STATUS.BAD_REQUEST
      );
      res.status(statusCode).json(response);
    }
  };

  // Clear cart
  clearCart = async (req: Request, res: Response): Promise<void> => {
    try {
      const token = req.cookies?.auth_token || req.headers.authorization?.replace('Bearer ', '');
      
      if (!token) {
        const { response, statusCode } = createErrorResponse(
          'User not authenticated',
          HTTP_STATUS.UNAUTHORIZED
        );
        res.status(statusCode).json(response);
        return;
      }

      const user = verifyJwt(token);
      if (!user || !user.email) {
        const { response, statusCode } = createErrorResponse(
          'Invalid token',
          HTTP_STATUS.UNAUTHORIZED
        );
        res.status(statusCode).json(response);
        return;
      }

      const cart = await Cart.findOne({ 'user.email': user.email });

      if (!cart) {
        const { response, statusCode } = createErrorResponse(
          'Cart not found',
          HTTP_STATUS.NOT_FOUND
        );
        res.status(statusCode).json(response);
        return;
      }

      cart.items = [];
      await cart.save();

      const { response, statusCode } = createSuccessResponse(
        cart,
        'Cart cleared successfully'
      );
      res.status(statusCode).json(response);
    } catch (error: any) {
      console.error('Error clearing cart:', error);
      const { response, statusCode } = createErrorResponse(
        error.message || 'Failed to clear cart',
        HTTP_STATUS.BAD_REQUEST
      );
      res.status(statusCode).json(response);
    }
  };
}

export default CartController;


