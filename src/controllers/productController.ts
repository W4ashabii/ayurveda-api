import { Request, Response } from 'express';
import Product from '../models/Product';
import { createSuccessResponse, createErrorResponse } from '../utils';
import { HTTP_STATUS, API_MESSAGES } from '../constant';

class ProductController {
  // Get all products
  getAllProducts = async (req: Request, res: Response): Promise<void> => {
    try {
      const { category, featured } = req.query;
      const filter: any = {};

      if (category) {
        filter.category = category;
      }
      if (featured === 'true') {
        filter.featured = true;
      }

      const products = await Product.find(filter).sort({ createdAt: -1 });
      const { response, statusCode } = createSuccessResponse(
        products,
        'Products retrieved successfully'
      );
      res.status(statusCode).json(response);
    } catch (error) {
      console.error('Error fetching products:', error);
      const { response, statusCode } = createErrorResponse('Internal server error');
      res.status(statusCode).json(response);
    }
  };

  // Get product by ID
  getProductById = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const product = await Product.findById(id);

      if (!product) {
        const { response, statusCode } = createErrorResponse(
          API_MESSAGES.PRODUCT_NOT_FOUND,
          HTTP_STATUS.NOT_FOUND
        );
        res.status(statusCode).json(response);
        return;
      }

      const { response, statusCode } = createSuccessResponse(
        product,
        'Product retrieved successfully'
      );
      res.status(statusCode).json(response);
    } catch (error) {
      console.error('Error fetching product:', error);
      const { response, statusCode } = createErrorResponse('Internal server error');
      res.status(statusCode).json(response);
    }
  };

  // Create product (admin only)
  createProduct = async (req: Request, res: Response): Promise<void> => {
    try {
      const productData = req.body;
      const product = new Product(productData);
      await product.save();

      const { response, statusCode } = createSuccessResponse(
        product,
        API_MESSAGES.PRODUCT_CREATED,
        HTTP_STATUS.CREATED
      );
      res.status(statusCode).json(response);
    } catch (error: any) {
      console.error('Error creating product:', error);
      const { response, statusCode } = createErrorResponse(
        error.message || 'Failed to create product',
        HTTP_STATUS.BAD_REQUEST
      );
      res.status(statusCode).json(response);
    }
  };

  // Update product (admin only)
  updateProduct = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const productData = req.body;

      const product = await Product.findByIdAndUpdate(id, productData, {
        new: true,
        runValidators: true,
      });

      if (!product) {
        const { response, statusCode } = createErrorResponse(
          API_MESSAGES.PRODUCT_NOT_FOUND,
          HTTP_STATUS.NOT_FOUND
        );
        res.status(statusCode).json(response);
        return;
      }

      const { response, statusCode } = createSuccessResponse(
        product,
        API_MESSAGES.PRODUCT_UPDATED
      );
      res.status(statusCode).json(response);
    } catch (error: any) {
      console.error('Error updating product:', error);
      const { response, statusCode } = createErrorResponse(
        error.message || 'Failed to update product',
        HTTP_STATUS.BAD_REQUEST
      );
      res.status(statusCode).json(response);
    }
  };

  // Delete product (admin only)
  deleteProduct = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const product = await Product.findByIdAndDelete(id);

      if (!product) {
        const { response, statusCode } = createErrorResponse(
          API_MESSAGES.PRODUCT_NOT_FOUND,
          HTTP_STATUS.NOT_FOUND
        );
        res.status(statusCode).json(response);
        return;
      }

      const { response, statusCode } = createSuccessResponse(
        null,
        API_MESSAGES.PRODUCT_DELETED
      );
      res.status(statusCode).json(response);
    } catch (error) {
      console.error('Error deleting product:', error);
      const { response, statusCode } = createErrorResponse('Internal server error');
      res.status(statusCode).json(response);
    }
  };
}

export default ProductController;
