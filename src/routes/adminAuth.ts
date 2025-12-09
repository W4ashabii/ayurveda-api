import { Router, Request, Response } from 'express';
import passport from '../config/passport';
import { signJwt, verifyJwt } from '../config/passport';
import { createSuccessResponse, createErrorResponse } from '../utils';
import { HTTP_STATUS } from '../constant';
import Admin from '../models/Admin';

const router: Router = Router();

// Google OAuth login
router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
  })
);

// Google OAuth callback
router.get(
  '/google/callback',
  passport.authenticate('google', { failureRedirect: `${process.env.CLIENT_URL}/login?error=auth_failed` }),
  async (req: Request, res: Response) => {
    try {
      const user = req.user as any;
      const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim()).filter(Boolean);
      
      // Determine user role: admin if email is in admin list, otherwise user
      const isAdmin = adminEmails.length > 0 && adminEmails.includes(user.email);
      const userRole = isAdmin ? 'admin' : 'user';

      // Save or update user in database
      await Admin.findOneAndUpdate(
        { email: user.email },
        { email: user.email, role: userRole },
        { upsert: true, new: true }
      );

      // Generate JWT
      const token = signJwt({
        id: user.id,
        name: user.name,
        email: user.email,
        picture: user.picture,
        role: userRole,
      });

      // Set cookie and redirect
      // For cross-origin cookies in production, use sameSite: 'none' and secure: true
      const isProduction = process.env.NODE_ENV === 'production';
      res.cookie('auth_token', token, {
        httpOnly: true,
        secure: isProduction, // Must be true for sameSite: 'none'
        sameSite: isProduction ? 'none' : 'lax', // 'none' for cross-origin, 'lax' for same-origin
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      // Redirect admins to dashboard, normal users to homepage
      const redirectUrl = isAdmin 
        ? `${process.env.CLIENT_URL}/admin/dashboard`
        : `${process.env.CLIENT_URL}/`;
      
      console.log('[OAuth] Successful login:', {
        email: user.email,
        role: userRole,
        redirectUrl,
        clientUrl: process.env.CLIENT_URL,
      });
      
      res.redirect(redirectUrl);
    } catch (error) {
      console.error('Auth callback error:', error);
      res.redirect(`${process.env.CLIENT_URL}/login?error=server_error`);
    }
  }
);

// Get current user
router.get('/me', (req: Request, res: Response) => {
  try {
    const token = req.cookies?.auth_token || req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.json({
        authenticated: false,
      });
    }

    const user = verifyJwt(token);
    if (!user) {
      return res.json({
        authenticated: false,
      });
    }
    const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim()).filter(Boolean);
    const isAdmin = adminEmails.length > 0 && adminEmails.includes(user.email);

    // Return authenticated: true for any logged-in user (admin or regular user)
    res.json({
      authenticated: true,
      isAdmin,
      user,
    });
  } catch (error) {
    res.json({
      authenticated: false,
    });
  }
});

// Logout
router.post('/logout', (req: Request, res: Response) => {
  res.clearCookie('auth_token');
  const { response, statusCode } = createSuccessResponse(null, 'Logged out successfully');
  res.status(statusCode).json(response);
});

export default router;
