import 'dotenv/config';
import express, { type Application } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import connectDB, { getConnectionStatus } from './config/database';
import errorHandler from './middleware/errorHandler';
import notFoundHandler from './middleware/notFoundHandler';
import { configurePassport } from './config/passport';
import passport from './config/passport';
import { createSuccessResponse } from './utils';
import { HTTP_STATUS } from './constant';

// Import routes
import productRoutes from './routes/productRoutes';
import orderRoutes from './routes/orderRoutes';
import adminAuthRoutes from './routes/adminAuth';
import cartRoutes from './routes/cartRoutes';
import uploadRoutes from './routes/uploadRoutes';

const app: Application = express();

// Trust proxy
app.set('trust proxy', 1);

// CORS - Support multiple origins (comma-separated) or single origin
const allowedOrigins = process.env.CLIENT_URL 
  ? process.env.CLIENT_URL.split(',').map(url => url.trim())
  : ['http://localhost:5173'];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like OAuth redirects, mobile apps, curl requests)
      if (!origin) {
        console.log('[CORS] Allowing request with no origin');
        return callback(null, true);
      }
      
      // Check if origin is in allowed list
      if (allowedOrigins.indexOf(origin) !== -1) {
        console.log(`[CORS] Allowing origin: ${origin}`);
        callback(null, true);
      } else {
        // In production, be more permissive for OAuth redirects
        // Allow if it's a redirect from Google OAuth or same domain
        if (process.env.NODE_ENV === 'production') {
          // Allow Google OAuth redirects
          if (origin.includes('accounts.google.com') || origin.includes('googleusercontent.com')) {
            console.log(`[CORS] Allowing Google OAuth origin: ${origin}`);
            return callback(null, true);
          }
        }
        console.warn(`[CORS] Blocked origin: ${origin}. Allowed origins: ${allowedOrigins.join(', ')}`);
        callback(new Error(`Not allowed by CORS. Origin: ${origin}`));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session
const isProduction = process.env.NODE_ENV === 'production';
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: isProduction, // Must be true for sameSite: 'none'
      httpOnly: true,
      sameSite: isProduction ? 'none' : 'lax', // 'none' for cross-origin in production
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
  })
);

// Passport
configurePassport();
app.use(passport.initialize());
app.use(passport.session());

// API routes
app.use('/api/products', productRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/auth', adminAuthRoutes);
app.use('/api/cart', cartRoutes);
app.use('/api/upload', uploadRoutes);

// Health check
app.get('/health', (req, res) => {
  const payload = {
    message: 'API is running',
    timestamp: new Date().toISOString(),
    database: getConnectionStatus() ? 'connected' : 'disconnected',
  };
  const { response, statusCode } = createSuccessResponse(payload, 'OK', HTTP_STATUS.OK);
  res.status(statusCode).json(response);
});

// 404 handler
app.use(notFoundHandler);

// Error handler
app.use(errorHandler);

// Bootstrap
async function bootstrap() {
  try {
    await connectDB();
  } catch (err) {
    console.error('Failed to connect to MongoDB. Exiting.');
    process.exit(1);
  }

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📡 API Base URL: http://localhost:${PORT}/api`);
    console.log(`🏥 Health check: http://localhost:${PORT}/health`);
  });
}

bootstrap();

export default app;
