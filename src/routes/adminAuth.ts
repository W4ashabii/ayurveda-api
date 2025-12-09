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
      const cookieOptions: any = {
        httpOnly: true,
        secure: isProduction, // Must be true for sameSite: 'none'
        sameSite: (isProduction ? 'none' : 'lax') as 'none' | 'lax', // 'none' for cross-origin, 'lax' for same-origin
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/', // Ensure cookie is available across all routes
        // DO NOT set domain - let browser handle it for cross-origin cookies
      };
      
      res.cookie('auth_token', token, cookieOptions);
      
      // Log cookie details including Set-Cookie header
      const setCookieHeader = res.getHeader('Set-Cookie');
      console.log('[OAuth] Cookie set successfully:', {
        email: user.email,
        role: userRole,
        cookieOptions: {
          httpOnly: cookieOptions.httpOnly,
          secure: cookieOptions.secure,
          sameSite: cookieOptions.sameSite,
          maxAge: cookieOptions.maxAge,
          path: cookieOptions.path,
          domain: cookieOptions.domain || 'not set (cross-origin)',
        },
        setCookieHeader: Array.isArray(setCookieHeader) ? setCookieHeader[0] : setCookieHeader,
        redirectUrl: isAdmin 
          ? `${clientUrl}/admin/dashboard`
          : `${clientUrl}/`,
      });

      // Validate CLIENT_URL
      if (!process.env.CLIENT_URL) {
        console.error('[OAuth] ERROR: CLIENT_URL environment variable is not set!');
        return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=server_error`);
      }
      
      // Ensure CLIENT_URL is a complete URL
      let clientUrl = process.env.CLIENT_URL.trim();
      if (!clientUrl.startsWith('http://') && !clientUrl.startsWith('https://')) {
        console.error(`[OAuth] ERROR: CLIENT_URL must start with http:// or https://. Current value: ${clientUrl}`);
        return res.redirect(`${clientUrl}/login?error=server_error`);
      }
      
      // Auto-fix http:// to https:// for production/Vercel domains
      if (process.env.NODE_ENV === 'production' && clientUrl.startsWith('http://')) {
        // Check if it's a production domain (Vercel, etc.)
        if (clientUrl.includes('vercel.app') || clientUrl.includes('.app') || clientUrl.includes('.com')) {
          const httpsUrl = clientUrl.replace('http://', 'https://');
          console.warn(`[OAuth] WARNING: CLIENT_URL uses http:// but should use https:// in production. Auto-fixing: ${clientUrl} → ${httpsUrl}`);
          clientUrl = httpsUrl;
        }
      }
      
      // Redirect admins to dashboard, normal users to homepage
      const redirectUrl = isAdmin 
        ? `${clientUrl}/admin/dashboard`
        : `${clientUrl}/`;
      
      console.log('[OAuth] Successful login:', {
        email: user.email,
        role: userRole,
        redirectUrl,
        clientUrl: clientUrl,
        clientUrlLength: clientUrl.length,
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
    // Debug: Log all cookies and headers
    const allCookies = req.cookies || {};
    const authHeader = req.headers.authorization;
    const origin = req.headers.origin;
    const referer = req.headers.referer;
    
    console.log('[Auth] /me - Request details:', {
      hasCookies: !!req.cookies,
      cookieKeys: Object.keys(allCookies),
      hasAuthHeader: !!authHeader,
      origin,
      referer,
    });
    
    const token = req.cookies?.auth_token || req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      console.log('[Auth] /me - No token found. Cookies:', allCookies, 'Auth header:', authHeader ? 'present' : 'missing');
      return res.json({
        authenticated: false,
      });
    }

    const user = verifyJwt(token);
    if (!user) {
      console.log('[Auth] /me - Invalid token (token exists but verification failed)');
      return res.json({
        authenticated: false,
      });
    }
    
    const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim()).filter(Boolean);
    const isAdmin = adminEmails.length > 0 && adminEmails.includes(user.email);

    console.log('[Auth] /me - User authenticated:', {
      email: user.email,
      isAdmin,
      tokenSource: req.cookies?.auth_token ? 'cookie' : 'header',
    });

    // Return authenticated: true for any logged-in user (admin or regular user)
    res.json({
      authenticated: true,
      isAdmin,
      user,
    });
  } catch (error) {
    console.error('[Auth] /me - Error:', error);
    res.json({
      authenticated: false,
    });
  }
});

// Logout
router.post('/logout', (req: Request, res: Response) => {
  const isProduction = process.env.NODE_ENV === 'production';
  // Clear cookie with same options used when setting it
  res.clearCookie('auth_token', {
    httpOnly: true,
    secure: isProduction,
    sameSite: (isProduction ? 'none' : 'lax') as 'none' | 'lax',
    path: '/',
  });
  
  console.log('[Auth] Cookie cleared - user logged out');
  const { response, statusCode } = createSuccessResponse(null, 'Logged out successfully');
  res.status(statusCode).json(response);
});

export default router;
