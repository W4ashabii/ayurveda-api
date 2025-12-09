import { Request, Response, NextFunction } from 'express';
import { HTTP_STATUS, API_MESSAGES } from '../constant';

interface CustomError extends Error {
  statusCode?: number;
  status?: string;
  isOperational?: boolean;
}

const errorHandler = (
  err: CustomError,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  let error = { ...err };
  error.message = err.message;

  console.error('Error:', err);

  // Set CORS headers even on error to prevent CORS errors (very permissive)
  const origin = req.headers.origin;
  if (origin) {
    // Always allow origin - be very permissive
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
  } else {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  // Bad ObjectId
  if (err.name === 'CastError') {
    const message = 'Resource not found';
    error = { message, statusCode: HTTP_STATUS.NOT_FOUND } as CustomError;
  }

  // Duplicate key
  if (err.name === 'MongoError' && (err as any).code === 11000) {
    const message = 'Duplicate field value entered';
    error = { message, statusCode: HTTP_STATUS.BAD_REQUEST } as CustomError;
  }

  // Validation error
  if (err.name === 'ValidationError') {
    const message = Object.values((err as any).errors)
      .map((val: any) => val.message)
      .join(', ');
    error = { message, statusCode: HTTP_STATUS.BAD_REQUEST } as CustomError;
  }

  res.status(error.statusCode || HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
    success: false,
    message: error.message || API_MESSAGES.INTERNAL_ERROR,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
};

export default errorHandler;
