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

// CORS
app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
  })
);

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
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
