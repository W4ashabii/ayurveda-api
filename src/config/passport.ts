import passport from 'passport';
import { Strategy as GoogleStrategy, Profile } from 'passport-google-oauth20';
import jwt, { type Secret, type SignOptions } from 'jsonwebtoken';
import type { Request } from 'express';

export interface JwtUser {
  id: string;
  name: string;
  email: string;
  picture?: string;
  role?: string;
}

export function signJwt(user: JwtUser): string {
  const secret: Secret = (process.env.JWT_SECRET || 'dev-secret') as Secret;
  const options: SignOptions = {};
  const expiresInEnv = process.env.JWT_EXPIRES_IN || '7d';
  (options as any).expiresIn = expiresInEnv;
  return jwt.sign(user as any, secret, options as any);
}

export function verifyJwt(token: string): JwtUser | null {
  try {
    const secret: Secret = (process.env.JWT_SECRET || 'dev-secret') as Secret;
    return jwt.verify(token, secret) as JwtUser;
  } catch {
    return null;
  }
}

export function configurePassport(): boolean {
  const clientID = process.env.GOOGLE_CLIENT_ID || '';
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET || '';
  const callbackURL = process.env.OAUTH_CALLBACK_URL || '/api/auth/google/callback';
  const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim()).filter(Boolean);

  if (!clientID || !clientSecret) {
    console.warn('[auth] Google OAuth not configured. Missing client id/secret.');
    return false;
  }

  passport.use(
    new GoogleStrategy(
      {
        clientID,
        clientSecret,
        callbackURL,
        passReqToCallback: true,
      },
      async (_req: Request, _accessToken: string, _refreshToken: string, profile: Profile, done) => {
        try {
          const email = profile.emails?.[0]?.value || '';
          
          // Check if email is in admin list
          const isAdmin = adminEmails.length > 0 && adminEmails.includes(email);
          
          const user: JwtUser = {
            id: profile.id,
            name: profile.displayName,
            email,
            picture: profile.photos?.[0]?.value,
            role: isAdmin ? 'admin' : undefined,
          };
          
          return done(null, user);
        } catch (err) {
          return done(err as Error);
        }
      }
    )
  );
  
  passport.serializeUser((user: any, done) => {
    done(null, user);
  });

  passport.deserializeUser((user: any, done) => {
    done(null, user);
  });

  console.info('[auth] Google OAuth strategy configured with callback:', callbackURL);
  return true;
}

export default passport;
