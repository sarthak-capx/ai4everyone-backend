import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import { createClient } from '@supabase/supabase-js';
import authRoutes from './routes/auth';
import apiKeysRoutes from './routes/apiKeys';
import balanceRoutes from './routes/balance';
import proxyRoutes from './routes/proxy';
import verifyRoutes from './routes/verify';
import usageRoutes from './routes/usage';
import logsRoutes from './routes/logs';
import paymentsRoutes from './routes/payment';
import moralisRoutes from './routes/moralis';
import type { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import crypto, { createPrivateKey, createPublicKey } from 'crypto';
import session from 'express-session';
import { createCorsMiddleware } from './config/cors';
import { csrfTokenRoute, csrfValidation } from './middleware/csrf';
import { getSessionMiddleware } from './middleware/session';
import { createUserRateLimiter, createIpRateLimiter, createPaymentRateLimiter, createProxyRateLimiter } from './config/rateLimit';


// =========================
// Application Error Handling
// =========================
export class AppError extends Error {
  statusCode: number;
  isOperational: boolean;
  constructor(statusCode: number, message: string, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    Object.setPrototypeOf(this, AppError.prototype);
  }
}

// Centralized error responder (last middleware)
const globalErrorHandler = (err: Error, req: Request, res: Response, next: NextFunction) => {
  const requestId = (req as any).id;
  const timestamp = new Date().toISOString();

  // Minimal error logging (no stack traces or sensitive data)
  console.error('Error:', {
    requestId,
    timestamp,
    message: err.message,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: process.env.NODE_ENV === 'production' ? '[REDACTED]' : req.headers['user-agent']
  });

  let statusCode = 500;
  if (err instanceof AppError) {
    statusCode = err.statusCode;
  }

  return res.status(statusCode).json({
    success: false,
    error: 'An error occurred',
    requestId,
    timestamp
  });
};


// =========================
// App Bootstrap
// =========================
const app = express();

// Security headers (CSP tailored for AI/media)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: [
        "'self'",
        "https://fal.run",
        "https://api.inference.net",
        "https://api.coingecko.com",
        "https://api.supabase.co"
      ],
      mediaSrc: ["'self'", "https:", "blob:"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'same-origin' }
}));

// Additional baseline headers
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=()');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  next();
});

// Request ID for traceability
app.use((req: Request, res: Response, next: NextFunction) => {
  (req as any).id = crypto.randomUUID();
  res.setHeader('X-Request-ID', (req as any).id);
  next();
});

// Basic health endpoints (public)
app.get('/', (req, res) => {
  res.json({ message: 'API is working!' });
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Server is running' });
});

// =========================
// Webhooks (mounted before CORS)
// =========================
// Moralis webhooks (server-to-server, often without Origin header)
app.use('/webhooks/moralis', express.raw({ type: '*/*' }), (req: any, _res, next) => {
  req.rawBody = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '';
  try {
    req.body = req.rawBody ? JSON.parse(req.rawBody) : {};
  } catch {
    req.body = {};
  }
  next();
}, moralisRoutes);

// =========================
// CORS Configuration
// =========================
app.use(createCorsMiddleware());

// =========================
// Sessions
// =========================
// Session store & config moved to ./middleware/session
class ProductionSessionStore extends session.Store {
  private sessions: Map<string, { data: any; expires: number }> = new Map();
  private cleanupInterval: NodeJS.Timeout;
  private readonly MAX_SESSIONS = 10000;
  private readonly CLEANUP_INTERVAL = 5 * 60 * 1000;
  private readonly MAX_SESSION_SIZE = 1024 * 1024;

  constructor() {
    super();
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, this.CLEANUP_INTERVAL);

    process.on('SIGTERM', () => this.cleanupOnShutdown());
    process.on('SIGINT', () => this.cleanupOnShutdown());
    process.on('exit', () => this.cleanupOnShutdown());
  }

  private cleanup() {
    try {
      const now = Date.now();
      let deletedCount = 0;
      for (const [sid, session] of this.sessions.entries()) {
        if (session.expires < now) {
          this.sessions.delete(sid);
          deletedCount++;
        }
      }
      if (this.sessions.size > this.MAX_SESSIONS) {
        const entries = Array.from(this.sessions.entries());
        entries.sort((a, b) => a[1].expires - b[1].expires);
        const toDelete = entries.slice(0, this.sessions.size - this.MAX_SESSIONS);
        toDelete.forEach(([sid]) => {
          this.sessions.delete(sid);
          deletedCount++;
        });
        console.warn(`Session store memory limit exceeded. Deleted ${toDelete.length} oldest sessions.`);
      }
      if (deletedCount > 0) {
        console.log(`Session cleanup: deleted ${deletedCount} sessions. Current sessions: ${this.sessions.size}`);
      }
    } catch (error) {
      console.error('Session cleanup failed:', error);
    }
  }

  get(sid: string, callback: (err: any, session?: any) => void) {
    try {
      const session = this.sessions.get(sid);
      if (!session) {
        return callback(null, null);
      }
      if (session.expires < Date.now()) {
        this.sessions.delete(sid);
        return callback(null, null);
      }
      callback(null, session.data);
    } catch (error) {
      console.error('Session get error:', error);
      callback(error, null);
    }
  }

  set(sid: string, session: any, callback?: (err?: any) => void) {
    try {
      const sessionSize = JSON.stringify(session).length;
      if (sessionSize > this.MAX_SESSION_SIZE) {
        const error = new Error('Session data too large');
        console.error('Session size limit exceeded:', sessionSize, 'bytes');
        return callback?.(error);
      }
      if (this.sessions.size >= this.MAX_SESSIONS) {
        this.cleanup();
        if (this.sessions.size >= this.MAX_SESSIONS) {
          const error = new Error('Session store at capacity');
          console.error('Session store at capacity, rejecting new session');
          return callback?.(error);
        }
      }
      const expires = Date.now() + (session.cookie?.maxAge || 24 * 60 * 60 * 1000);
      this.sessions.set(sid, { data: session, expires });
      callback?.();
    } catch (error) {
      console.error('Session set error:', error);
      callback?.(error);
    }
  }

  destroy(sid: string, callback?: (err?: any) => void) {
    try {
      this.sessions.delete(sid);
      callback?.();
    } catch (error) {
      console.error('Session destroy error:', error);
      callback?.(error);
    }
  }

  touch(sid: string, session: any, callback?: (err?: any) => void) {
    try {
      const existing = this.sessions.get(sid);
      if (existing) {
        existing.expires = Date.now() + (session.cookie?.maxAge || 24 * 60 * 60 * 1000);
      }
      callback?.();
    } catch (error) {
      console.error('Session touch error:', error);
      callback?.(error);
    }
  }

  // Cleanup hooks on shutdown
  cleanupOnShutdown() {
    try {
      if (this.cleanupInterval) {
        clearInterval(this.cleanupInterval);
        this.cleanupInterval = null as any;
      }
      this.sessions.clear();
      console.log('Session store destroyed successfully');
    } catch (error) {
      console.error('Session store destroy error:', error);
    }
  }
}

// Validate session secret
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must be set and at least 32 characters long');
}

// Session configuration
const sessionConfig: session.SessionOptions = {
  secret: process.env.SESSION_SECRET as string,
  name: 'ai4everyone.sid',
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'none',
    maxAge: 24 * 60 * 60 * 1000,
    path: '/'
  },
  resave: false,
  saveUninitialized: false,
  rolling: true,
  unset: 'destroy'
};

if (process.env.NODE_ENV === 'production') {
  sessionConfig.store = new ProductionSessionStore();
} else {
  sessionConfig.store = new session.MemoryStore();
  console.warn('Using MemoryStore in development - this is fine for local development');
}

app.use(getSessionMiddleware());


// =========================
// JWT Keys
// =========================
if (!process.env.JWT_PRIVATE_KEY) {
  throw new Error('JWT_PRIVATE_KEY must be set as environment variable');
}

if (!process.env.JWT_PUBLIC_KEY) {
  throw new Error('JWT_PUBLIC_KEY must be set as environment variable');
}

let jwtPrivateKey: any;
let jwtPublicKey: any;

try {
  jwtPrivateKey = createPrivateKey(process.env.JWT_PRIVATE_KEY);
  jwtPublicKey = createPublicKey(process.env.JWT_PUBLIC_KEY);
} catch (error) {
  throw new Error('Invalid JWT key format. Keys must be valid PEM format.');
}

export { jwtPrivateKey, jwtPublicKey };


// =========================
// CSRF (optional)
// =========================
app.get('/api/csrf-token', csrfTokenRoute);
export { csrfValidation };


// =========================
// Parsers
// =========================
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// File uploads: 25mb (adjust the route as needed)
app.use('/api/upload', express.json({ limit: '25mb' }));
app.use('/api/upload', express.urlencoded({ extended: true, limit: '25mb' }));


// =========================
// Supabase clients
// =========================
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseAnonKey) {
  throw new Error('Missing Supabase credentials');
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: { persistSession: false }
});

// Anon client for SECURITY DEFINER RPCs
export const supabaseAnon = createClient(supabaseUrl, supabaseAnonKey, {
  auth: { persistSession: false }
});

// User-scoped client (service role)
export const getUserSupabaseClient = (userId: string) => {
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error('SUPABASE_SERVICE_ROLE_KEY is not configured');
  }
  if (!userId) {
    throw new Error('Missing userId for user-scoped Supabase client');
  }
  return createClient(supabaseUrl, process.env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false }
  });
};


// =========================
// Rate limiting
// =========================
const userRateLimiter = createUserRateLimiter();

const ipRateLimiter = createIpRateLimiter();

// Payment-specific (POST only)
const paymentRateLimiter = createPaymentRateLimiter();

// Simple idempotency key capture placeholder
const paymentIdempotencyCheck = (req: Request, res: Response, next: NextFunction) => {
  const txHash = req.body.txHash || req.body.txSignature;
  const userId = req.body.userId;
  if (!txHash || !userId) {
    return next();
  }
  const key = `payment:${txHash}:${userId}`;
  next();
};


// =========================
// Routes
// =========================
// Auth
app.use('/auth', ipRateLimiter, authRoutes);

// API Keys
app.use('/api-keys', userRateLimiter, apiKeysRoutes);

// Balance
app.use('/balance', userRateLimiter, balanceRoutes);

// Usage
app.use('/usage', usageRoutes);

// Logs
app.use('/logs', logsRoutes);

// Verify
app.use('/verify', paymentRateLimiter, paymentIdempotencyCheck, verifyRoutes);

// Payments
app.use('/payments', paymentRateLimiter, paymentsRoutes);

// Moralis (already mounted before CORS for raw body & no-Origin)
app.use('/webhooks/moralis', moralisRoutes);

// Proxy (last)
const proxyRateLimiter = createProxyRateLimiter();

app.use('/', proxyRateLimiter, proxyRoutes);


// =========================
// Tail
// =========================
app.use(globalErrorHandler);

if (process.env.NODE_ENV === 'production') {
  console.log = () => { };
  console.error = () => { };
  console.warn = () => { };
}

const startServer = async (port: number, maxRetries: number = 5) => {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      await new Promise<void>((resolve, reject) => {
        const server = app.listen(port, () => {
          resolve();
        });
        server.on('error', (error: any) => {
          if (error.code === 'EADDRINUSE') {
            if (process.env.NODE_ENV !== 'production') {
            }
            reject(error);
          } else {
            reject(error);
          }
        });
      });
      return;
    } catch (error: any) {
      if (error.code === 'EADDRINUSE' && attempt < maxRetries) {
        port++;
        continue;
      }
      throw error;
    }
  }
  throw new Error(`Failed to start server after ${maxRetries} attempts`);
};

const initialPort = parseInt(process.env.PORT || '5000', 10);
startServer(initialPort); 