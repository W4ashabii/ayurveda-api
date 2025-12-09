import { Request, Response } from 'express';
import { HTTP_STATUS } from '../constant';

const notFoundHandler = (req: Request, res: Response): void => {
  res.status(HTTP_STATUS.NOT_FOUND).json({
    success: false,
    message: `Route ${req.originalUrl} not found`,
  });
};

export default notFoundHandler;
