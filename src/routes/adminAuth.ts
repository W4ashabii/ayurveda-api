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
      
      console.log('[OAuth] User authentication details:', {
        email: user.email,
        adminEmails: adminEmails,
        isAdmin,
        userRole,
        adminEmailsLength: adminEmails.length,
      });

      // Save or update user in database
      await Admin.findOneAndUpdate(
        { email: user.email },
        { email: user.email, role: userRole },
        { upsert: true, new: true }
      );

      // Generate JWT with error handling
      let token: string;
      try {
        token = signJwt({
          id: user.id,
          name: user.name,
          email: user.email,
          picture: user.picture,
          role: userRole,
        });
      } catch (jwtError: any) {
        console.error('[OAuth] Failed to generate JWT token:', jwtError.message || jwtError);
        return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=server_error`);
      }
      
      if (!token) {
        console.error('[OAuth] JWT token generation returned empty token');
        return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=server_error`);
      }

      // Validate and prepare CLIENT_URL first (before using it)
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
      
      // Determine redirect URL based on user role
      // Remove any trailing slashes from clientUrl to avoid double slashes
      const cleanClientUrl = clientUrl.replace(/\/+$/, '');
      
      // Add token to URL as fallback if cookies don't work (temporary, will be replaced by cookie)
      // This helps with cross-origin cookie issues
      const tokenParam = `?token=${encodeURIComponent(token)}`;
      const redirectUrl = isAdmin 
        ? `${cleanClientUrl}/admin/dashboard${tokenParam}`
        : `${cleanClientUrl}/${tokenParam}`;
      
      // Set cookie and redirect
      // For cross-origin cookies in production, use sameSite: 'none' and secure: true
      const isProduction = process.env.NODE_ENV === 'production';
      
      // Extract domain from backend URL for cookie domain setting (if needed)
      // For Vercel, cookies should work without explicit domain, but we'll set it for cross-origin
      const backendUrl = new URL(process.env.OAUTH_CALLBACK_URL || `http://localhost:3000/api/auth/google/callback`);
      const backendDomain = backendUrl.hostname;
      
      // For cross-origin cookies, we MUST use sameSite: 'none' and secure: true
      // Even if NODE_ENV is not production, if we're on HTTPS (Vercel), use secure cookies
      const isHTTPS = req.protocol === 'https' || req.get('x-forwarded-proto') === 'https';
      const cookieOptions: any = {
        httpOnly: true,
        // Force secure for HTTPS (required for sameSite: 'none')
        secure: isHTTPS || isProduction,
        // Force 'none' for cross-origin (required for cross-domain cookies)
        sameSite: 'none' as 'none',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/', // Ensure cookie is available across all routes
        // DO NOT set domain - let browser handle it for cross-origin
      };
      
      console.log('[OAuth] Cookie options:', {
        secure: cookieOptions.secure,
        sameSite: cookieOptions.sameSite,
        isHTTPS,
        isProduction,
        protocol: req.protocol,
        forwardedProto: req.get('x-forwarded-proto'),
      });
      
      // Set additional CORS headers to ensure cookie is accepted
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Origin', cleanClientUrl);
      
      // Set cookie BEFORE redirect
      res.cookie('auth_token', token, cookieOptions);
      
      // Verify cookie was set - check multiple ways
      const setCookieHeader = res.getHeader('Set-Cookie');
      const cookieHeaderValue = Array.isArray(setCookieHeader) 
        ? setCookieHeader[0] 
        : (typeof setCookieHeader === 'string' ? setCookieHeader : String(setCookieHeader));
      
      // Also check response headers directly
      const allHeaders = res.getHeaders();
      const setCookieFromHeaders = allHeaders['set-cookie'];
      
      console.log('[OAuth] ===== COOKIE SETTING DEBUG =====');
      console.log('[OAuth] Request details:', {
        protocol: req.protocol,
        secure: req.secure,
        hostname: req.hostname,
        headers: {
          'x-forwarded-proto': req.get('x-forwarded-proto'),
          'x-forwarded-host': req.get('x-forwarded-host'),
          host: req.get('host'),
        },
      });
      console.log('[OAuth] Cookie options:', cookieOptions);
      console.log('[OAuth] Set-Cookie header (from getHeader):', setCookieHeader);
      console.log('[OAuth] Set-Cookie header (from getHeaders):', setCookieFromHeaders);
      console.log('[OAuth] All response headers:', Object.keys(allHeaders));
      
      if (!cookieHeaderValue || (typeof cookieHeaderValue === 'string' && !cookieHeaderValue.includes('auth_token'))) {
        console.error('[OAuth] ⚠️⚠️⚠️ ERROR: Cookie was not set! ⚠️⚠️⚠️');
        console.error('[OAuth] Set-Cookie header value:', cookieHeaderValue);
        console.error('[OAuth] Set-Cookie header type:', typeof setCookieHeader);
        console.error('[OAuth] Set-Cookie header raw:', setCookieHeader);
      } else {
        console.log('[OAuth] ✅ Cookie header confirmed:', cookieHeaderValue.substring(0, 100) + '...');
      }
      
      console.log('[OAuth] Cookie set successfully:', {
        email: user.email,
        role: userRole,
        isAdmin,
        cookieOptions: {
          httpOnly: cookieOptions.httpOnly,
          secure: cookieOptions.secure,
          sameSite: cookieOptions.sameSite,
          maxAge: cookieOptions.maxAge,
          path: cookieOptions.path,
          domain: cookieOptions.domain || 'not set (cross-origin)',
        },
        setCookieHeader: cookieHeaderValue,
        setCookieHeaderLength: typeof cookieHeaderValue === 'string' ? cookieHeaderValue.length : 0,
        redirectUrl,
        clientUrl: cleanClientUrl,
        isProduction,
        isHTTPS,
      });
      console.log('[OAuth] ===== END COOKIE DEBUG =====');
      
      console.log('[OAuth] Redirecting to:', redirectUrl);
      
      // Use 302 redirect (temporary) to ensure cookie is sent
      res.redirect(302, redirectUrl);
    } catch (error) {
      console.error('Auth callback error:', error);
      res.redirect(`${process.env.CLIENT_URL}/login?error=server_error`);
    }
  }
);

// Helper function to set CORS headers (very permissive)
const setCORSHeaders = (req: Request, res: Response): void => {
  const origin = req.headers.origin;
  if (origin) {
    // Always set CORS headers - be very permissive
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
  } else {
    // Even if no origin, set credentials header
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
};

// Test endpoint to check cookie setting
router.get('/test-cookie', (req: Request, res: Response) => {
  setCORSHeaders(req, res);
  
  const testToken = 'test-token-123';
  const isHTTPS = req.protocol === 'https' || req.get('x-forwarded-proto') === 'https';
  const isProduction = process.env.NODE_ENV === 'production';
  
  const cookieOptions: any = {
    httpOnly: true,
    secure: isHTTPS || isProduction,
    sameSite: 'none' as 'none',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
  };
  
  res.cookie('test_cookie', testToken, cookieOptions);
  
  const setCookieHeader = res.getHeader('Set-Cookie');
  
  res.json({
    success: true,
    message: 'Test cookie set',
    requestInfo: {
      protocol: req.protocol,
      secure: req.secure,
      hostname: req.hostname,
      forwardedProto: req.get('x-forwarded-proto'),
      forwardedHost: req.get('x-forwarded-host'),
    },
    cookieOptions,
    setCookieHeader: setCookieHeader,
    receivedCookies: req.cookies || {},
  });
});

// Get current user
router.get('/me', (req: Request, res: Response) => {
  // Set CORS headers FIRST, before any processing
  setCORSHeaders(req, res);
  
  try {
    // Safely get cookies (handle case where cookieParser might not have run)
    let allCookies: any = {};
    try {
      allCookies = req.cookies || {};
    } catch (cookieError) {
      console.warn('[Auth] /me - Error reading cookies:', cookieError);
      allCookies = {};
    }
    
    const authHeader = req.headers.authorization;
    const referer = req.headers.referer;
    const origin = req.headers.origin;
    
    console.log('[Auth] /me - ===== REQUEST DEBUG =====');
    console.log('[Auth] /me - Request details:', {
      hasCookies: !!req.cookies,
      cookieKeys: Object.keys(allCookies),
      cookieValues: allCookies,
      hasAuthHeader: !!authHeader,
      origin,
      referer,
      protocol: req.protocol,
      secure: req.secure,
      hostname: req.hostname,
      forwardedProto: req.get('x-forwarded-proto'),
      allHeaders: Object.keys(req.headers),
    });
    console.log('[Auth] /me - ===== END REQUEST DEBUG =====');
    
    // Safely extract token
    let token: string | undefined;
    try {
      token = allCookies?.auth_token || req.headers.authorization?.replace('Bearer ', '');
    } catch (tokenError) {
      console.error('[Auth] /me - Error extracting token:', tokenError);
      token = undefined;
    }
    
    if (!token) {
      console.log('[Auth] /me - No token found. Cookies:', allCookies, 'Auth header:', authHeader ? 'present' : 'missing');
      return res.json({
        authenticated: false,
      });
    }

    try {
      // Verify JWT with fallback handling
      const user = verifyJwt(token);
      
      if (!user) {
        console.log('[Auth] /me - Invalid token (token exists but verification failed)');
        return res.json({
          authenticated: false,
        });
      }
      
      // Validate user object has required fields
      if (!user.email || !user.id) {
        console.error('[Auth] /me - User object missing required fields:', user);
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
      return res.json({
        authenticated: true,
        isAdmin,
        user,
      });
    } catch (jwtError: any) {
      console.error('[Auth] /me - JWT verification error:', {
        error: jwtError.message || jwtError,
        name: jwtError.name,
        stack: process.env.NODE_ENV === 'development' ? jwtError.stack : undefined,
      });
      return res.json({
        authenticated: false,
      });
    }
  } catch (error) {
    console.error('[Auth] /me - Unexpected error:', error);
    // Ensure CORS headers are still set even on error
    setCORSHeaders(req, res);
    return res.json({
      authenticated: false,
    });
  }
});

// Set token cookie (fallback for cross-origin cookie issues)
router.post('/set-token', (req: Request, res: Response) => {
  setCORSHeaders(req, res);
  
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({
        success: false,
        message: 'Token is required',
      });
    }
    
    // Verify token is valid before setting cookie
    const user = verifyJwt(token);
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid token',
      });
    }
    
    // Set cookie with same options as OAuth callback
    const isHTTPS = req.protocol === 'https' || req.get('x-forwarded-proto') === 'https';
    const isProduction = process.env.NODE_ENV === 'production';
    
    const cookieOptions: any = {
      httpOnly: true,
      secure: isHTTPS || isProduction,
      sameSite: 'none' as 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/',
    };
    
    res.cookie('auth_token', token, cookieOptions);
    
    console.log('[Auth] Token cookie set via /set-token endpoint for user:', user.email);
    
    res.json({
      success: true,
      message: 'Token cookie set successfully',
    });
  } catch (error: any) {
    console.error('[Auth] Error setting token cookie:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to set token cookie',
    });
  }
});

// Logout
router.post('/logout', (req: Request, res: Response) => {
  setCORSHeaders(req, res);
  
  const isProduction = process.env.NODE_ENV === 'production';
  const isHTTPS = req.protocol === 'https' || req.get('x-forwarded-proto') === 'https';
  
  // Clear cookie with same options used when setting it
  res.clearCookie('auth_token', {
    httpOnly: true,
    secure: isHTTPS || isProduction,
    sameSite: 'none' as 'none',
    path: '/',
  });
  
  console.log('[Auth] Cookie cleared - user logged out');
  const { response, statusCode } = createSuccessResponse(null, 'Logged out successfully');
  res.status(statusCode).json(response);
});

export default router;
