import { Request, Response, NextFunction } from 'express';
import { verifyJwt, JwtUser } from '../config/passport';
import { HTTP_STATUS, API_MESSAGES } from '../constant';

export interface AuthRequest extends Request {
  user?: JwtUser;
}

export const adminAuth = (req: Request, res: Response, next: NextFunction): void => {
  const authReq = req as AuthRequest;
  
  // Set CORS headers first (less strict)
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
  }
  
  try {
    // Get token from cookie or Authorization header (less strict - try multiple sources)
    let token = req.cookies?.auth_token || 
                req.headers.authorization?.replace('Bearer ', '') ||
                req.headers.authorization ||
                req.body?.token ||
                req.query?.token;
    
    if (!token) {
      // Less strict: log but don't fail immediately
      console.warn('[adminAuth] No token found in request');
      res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        message: API_MESSAGES.UNAUTHORIZED,
      });
      return;
    }

    const user = verifyJwt(token);
    
    if (!user) {
      console.warn('[adminAuth] Token verification failed');
      res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        message: API_MESSAGES.UNAUTHORIZED,
      });
      return;
    }

    // Check if user is admin (less strict - allow if no admin emails configured)
    const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim()).filter(Boolean);
    
    // Less strict: if no admin emails configured, allow all authenticated users
    if (adminEmails.length > 0 && !adminEmails.includes(user.email)) {
      console.warn('[adminAuth] User is not admin:', user.email);
      res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        message: API_MESSAGES.ADMIN_REQUIRED,
      });
      return;
    }

    authReq.user = user;
    next();
  } catch (error: any) {
    console.error('[adminAuth] Error:', error.message || error);
    // Set CORS headers even on error
    if (origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    res.status(HTTP_STATUS.UNAUTHORIZED).json({
      success: false,
      message: API_MESSAGES.UNAUTHORIZED,
    });
  }
};
