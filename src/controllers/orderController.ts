import { Request, Response } from 'express';
import Order from '../models/Order';
import Product from '../models/Product';
import { createSuccessResponse, createErrorResponse } from '../utils';
import { HTTP_STATUS, API_MESSAGES } from '../constant';

class OrderController {
  // Create order
  createOrder = async (req: Request, res: Response): Promise<void> => {
    try {
      const {
        orderItems,
        shippingAddress,
        paymentMethod,
        itemsPrice,
        shippingPrice,
        taxPrice,
        totalPrice,
        user,
      } = req.body;

      // Validate shipping address - only Kathmandu and Pokhara in Nepal
      if (shippingAddress.country !== 'Nepal') {
        const { response, statusCode } = createErrorResponse(
          'We currently only deliver within Nepal',
          HTTP_STATUS.BAD_REQUEST
        );
        res.status(statusCode).json(response);
        return;
      }

      const allowedCities = ['Kathmandu', 'Pokhara'];
      if (!allowedCities.includes(shippingAddress.city)) {
        const { response, statusCode } = createErrorResponse(
          'Delivery is only available in Kathmandu and Pokhara',
          HTTP_STATUS.BAD_REQUEST
        );
        res.status(statusCode).json(response);
        return;
      }

      // Validate order items
      for (const item of orderItems) {
        const product = await Product.findById(item.product);
        if (!product) {
          const { response, statusCode } = createErrorResponse(
            `Product ${item.product} not found`,
            HTTP_STATUS.BAD_REQUEST
          );
          res.status(statusCode).json(response);
          return;
        }
        if (product.stock < item.quantity) {
          const { response, statusCode } = createErrorResponse(
            `Insufficient stock for ${product.name}`,
            HTTP_STATUS.BAD_REQUEST
          );
          res.status(statusCode).json(response);
          return;
        }
      }

      // Create order
      const order = new Order({
        orderItems,
        shippingAddress,
        paymentMethod,
        itemsPrice,
        shippingPrice,
        taxPrice,
        totalPrice,
        user,
        status: 'pending',
      });

      // Update product stock
      for (const item of orderItems) {
        await Product.findByIdAndUpdate(item.product, {
          $inc: { stock: -item.quantity },
        });
      }

      await order.save();

      const { response, statusCode } = createSuccessResponse(
        order,
        API_MESSAGES.ORDER_CREATED,
        HTTP_STATUS.CREATED
      );
      res.status(statusCode).json(response);
    } catch (error: any) {
      console.error('Error creating order:', error);
      const { response, statusCode } = createErrorResponse(
        error.message || 'Failed to create order',
        HTTP_STATUS.BAD_REQUEST
      );
      res.status(statusCode).json(response);
    }
  };

  // Get all orders (admin only)
  getAllOrders = async (req: Request, res: Response): Promise<void> => {
    try {
      const orders = await Order.find({}).sort({ createdAt: -1 }).populate('orderItems.product');
      const { response, statusCode } = createSuccessResponse(
        orders,
        'Orders retrieved successfully'
      );
      res.status(statusCode).json(response);
    } catch (error) {
      console.error('Error fetching orders:', error);
      const { response, statusCode } = createErrorResponse('Internal server error');
      res.status(statusCode).json(response);
    }
  };

  // Get order by ID
  getOrderById = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const order = await Order.findById(id).populate('orderItems.product');

      if (!order) {
        const { response, statusCode } = createErrorResponse(
          API_MESSAGES.ORDER_NOT_FOUND,
          HTTP_STATUS.NOT_FOUND
        );
        res.status(statusCode).json(response);
        return;
      }

      const { response, statusCode } = createSuccessResponse(
        order,
        'Order retrieved successfully'
      );
      res.status(statusCode).json(response);
    } catch (error) {
      console.error('Error fetching order:', error);
      const { response, statusCode } = createErrorResponse('Internal server error');
      res.status(statusCode).json(response);
    }
  };

  // Update order (admin only)
  updateOrder = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const updateData = req.body;

      const order = await Order.findByIdAndUpdate(id, updateData, {
        new: true,
        runValidators: true,
      });

      if (!order) {
        const { response, statusCode } = createErrorResponse(
          API_MESSAGES.ORDER_NOT_FOUND,
          HTTP_STATUS.NOT_FOUND
        );
        res.status(statusCode).json(response);
        return;
      }

      const { response, statusCode } = createSuccessResponse(
        order,
        API_MESSAGES.ORDER_UPDATED
      );
      res.status(statusCode).json(response);
    } catch (error: any) {
      console.error('Error updating order:', error);
      const { response, statusCode } = createErrorResponse(
        error.message || 'Failed to update order',
        HTTP_STATUS.BAD_REQUEST
      );
      res.status(statusCode).json(response);
    }
  };

  // Delete order (admin only)
  deleteOrder = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const order = await Order.findByIdAndDelete(id);

      if (!order) {
        const { response, statusCode } = createErrorResponse(
          API_MESSAGES.ORDER_NOT_FOUND,
          HTTP_STATUS.NOT_FOUND
        );
        res.status(statusCode).json(response);
        return;
      }

      const { response, statusCode } = createSuccessResponse(
        null,
        'Order deleted successfully'
      );
      res.status(statusCode).json(response);
    } catch (error: any) {
      console.error('Error deleting order:', error);
      const { response, statusCode } = createErrorResponse(
        error.message || 'Failed to delete order',
        HTTP_STATUS.BAD_REQUEST
      );
      res.status(statusCode).json(response);
    }
  };
}

export default OrderController;
