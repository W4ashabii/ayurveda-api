import { Request, Response } from 'express';
import { uploadToCloudinary } from '../config/cloudinary';
import { createSuccessResponse, createErrorResponse } from '../utils';
import { HTTP_STATUS } from '../constant';

class UploadController {
  // Upload image to Cloudinary
  uploadImage = async (req: Request, res: Response): Promise<void> => {
    try {
      if (!req.file) {
        const { response, statusCode } = createErrorResponse(
          'No image file provided',
          HTTP_STATUS.BAD_REQUEST
        );
        res.status(statusCode).json(response);
        return;
      }

      const result = await uploadToCloudinary(req.file.buffer, 'ayurveda-products');

      const { response, statusCode } = createSuccessResponse(
        {
          url: result.secure_url,
          publicId: result.public_id,
        },
        'Image uploaded successfully'
      );
      res.status(statusCode).json(response);
    } catch (error: any) {
      console.error('Error uploading image:', error);
      const { response, statusCode } = createErrorResponse(
        error.message || 'Failed to upload image',
        HTTP_STATUS.BAD_REQUEST
      );
      res.status(statusCode).json(response);
    }
  };
}

export default UploadController;

