import { Request, Response, NextFunction } from 'express';
import { verifyJwt, JwtUser } from '../config/passport';
import { HTTP_STATUS, API_MESSAGES } from '../constant';

export interface AuthRequest extends Request {
  user?: JwtUser;
}

export const adminAuth = (req: Request, res: Response, next: NextFunction): void => {
  const authReq = req as AuthRequest;
  try {
    // Get token from cookie or Authorization header
    const token = req.cookies?.auth_token || req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        message: API_MESSAGES.UNAUTHORIZED,
      });
      return;
    }

    const user = verifyJwt(token);
    
    if (!user) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        message: API_MESSAGES.UNAUTHORIZED,
      });
      return;
    }

    // Check if user is admin
    const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim()).filter(Boolean);
    
    if (adminEmails.length > 0 && !adminEmails.includes(user.email)) {
      res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        message: API_MESSAGES.ADMIN_REQUIRED,
      });
      return;
    }

    authReq.user = user;
    next();
  } catch (error) {
    res.status(HTTP_STATUS.UNAUTHORIZED).json({
      success: false,
      message: API_MESSAGES.UNAUTHORIZED,
    });
  }
};
