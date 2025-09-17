import express, { Request, Response, NextFunction } from 'express';
import { supabase, supabaseAnon, jwtPrivateKey } from '../index';
import { ethers } from 'ethers';
import { body, validationResult } from 'express-validator';
import { AppError } from '../index';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import session from 'express-session';

// Extend session interface to include userContext
declare module 'express-session' {
  interface SessionData {
    userContext?: {
      userId: string;
      email: string;
      walletAddress: string;
      deviceFingerprint: string;
      loginTime: number;
    };
  }
}

const router = express.Router();

// ✅ SECURE: Middleware to extract user context from session
export const getUserContext = (req: Request) => {
  return req.session.userContext;
};

// ✅ SECURE: Middleware to validate user session
export const requireUserContext = (req: Request, res: Response, next: NextFunction) => {
  const userContext = getUserContext(req);
  if (!userContext) {
    return next(new AppError(401, 'User session not found'));
  }
  next();
};

// Wallet-based login endpoint (no Supabase Auth, just profiles table)
router.post('/wallet-login', [
  body('address').isString().matches(/^0x[a-fA-F0-9]{40}$/).withMessage('Valid Ethereum address required'),
  body('signature').isString().withMessage('Signature is required'),
  body('message').isString().withMessage('Message is required'),
  body('timestamp').isNumeric().withMessage('Timestamp is required'),
], async (req: Request, res: Response, next: NextFunction) => {
  // ✅ SECURE: Regenerate session to prevent session fixation
  req.session.regenerate((err) => {
    if (err) {
      console.error('Session regeneration failed:', err);
      return next(new AppError(500, 'Session regeneration failed'));
    }
    
    // Log successful session regeneration for security monitoring
    console.log('Session regenerated successfully for authentication attempt:', {
      ip: req.ip,
      userAgent: req.headers['user-agent'] ? '[REDACTED]' : '[REDACTED]',
      timestamp: new Date().toISOString(),
      event: 'session_regeneration'
    });
    
    // Continue with authentication logic in the callback
    handleWalletLogin(req, res, next);
  });
});

// Separate function to handle the actual login logic
async function handleWalletLogin(req: Request, res: Response, next: NextFunction) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(new AppError(400, 'Validation error'));
  }
  const { address, signature, message, timestamp } = req.body;

  // Validate required fields
  if (!address || !signature || !message || !timestamp) {
    return next(new AppError(400, 'Missing required fields'));
  }

  // Verify timestamp (prevent replay attacks)
  const now = Date.now();
  const messageTime = parseInt(timestamp);
  if (Math.abs(now - messageTime) > 300000) { // 5 minutes
    return next(new AppError(401, 'Message expired'));
  }

  // Verify message format
  const expectedMessage = `AI4EVERYONE Login: ${address} at ${timestamp}`;
  if (message !== expectedMessage) {
    return next(new AppError(401, 'Invalid message format'));
  }

  // Verify signature
  try {
    const recoveredAddress = ethers.verifyMessage(message, signature);
    if (recoveredAddress.toLowerCase() !== address.toLowerCase()) {
      return next(new AppError(401, 'Invalid signature'));
    }
  } catch (error) {
    return next(new AppError(401, 'Signature verification failed'));
  }

  const walletAddress = address.toLowerCase();
  try {
    // Use SECURITY DEFINER RPC to bootstrap/read profile without service role
    let profile: any = null;
    try {
      const { data: rpcProfile } = await supabaseAnon
        .rpc('upsert_profile_for_wallet', { p_wallet: walletAddress })
        .single();
      if (rpcProfile) profile = rpcProfile;
    } catch {}

    // If RPC failed unexpectedly, bail out (safer than service-role fallback)
    if (!profile) {
      return next(new AppError(500, 'Failed to load or create profile'));
    }

    // JWT keys are already validated and loaded in index.ts
    if (!jwtPrivateKey) {
      return next(new AppError(500, 'JWT private key is not configured'));
    }

    // Generate device fingerprint for additional security
    const deviceFingerprint = crypto.createHash('sha256')
      .update(req.ip + (req.headers['user-agent'] || 'unknown'))
      .digest('hex');

    // ✅ SECURE: Store sensitive data in server-side session, not JWT
    req.session.userContext = {
      userId: profile.id,
      email: profile.email,
      walletAddress: walletAddress,
      deviceFingerprint: deviceFingerprint,
      loginTime: Date.now()
    };

    // ✅ SECURE: JWT contains only minimal, non-sensitive data
    const token = jwt.sign(
      {
        sub: profile.id,  // Subject claim (standard) - only user ID
        iat: Math.floor(Date.now() / 1000),  // Issued at
        jti: uuidv4(),  // Unique token ID for revocation
        type: 'access'
        // ❌ NO email, NO fingerprint, NO sensitive data in JWT
      },
      jwtPrivateKey,
      { 
        expiresIn: '1h',  // Balanced expiration
        algorithm: 'RS256',  // Asymmetric algorithm
        issuer: 'https://api.ai4everyone.com',
        audience: 'ai4everyone-api'
      }
    );
    
    // Audit the login event
    await supabaseAnon.rpc('audit_security_event', {
      p_event_type: 'wallet_login',
      p_user_id: profile.id,
      p_details: { 
        wallet_address: walletAddress,
        login_method: 'wallet_signature'
      }
    });
    
    res.status(200).json({ user: profile, token });
  } catch (err) {
    // More detailed error logging
    console.error('Wallet login error:', err);
    if (err instanceof Error) {
      next(new AppError(500, `Server error during wallet login: ${err.message}`));
    } else {
      next(new AppError(500, 'Server error during wallet login.'));
    }
  }
}

// Wallet configuration endpoint - serves WalletConnect project ID securely
router.get('/wallet-config', async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Check if WalletConnect project ID is configured
    if (!process.env.WALLET_CONNECT_PROJECT_ID) {
      return next(new AppError(500, 'WalletConnect project ID is not configured'));
    }

    // Return wallet configuration (project ID fetched at runtime, not embedded in build)
    res.status(200).json({
      projectId: process.env.WALLET_CONNECT_PROJECT_ID,
      appName: 'AI4EVERYONE'
    });
  } catch (err) {
    console.error('Wallet config error:', err);
    next(new AppError(500, 'Failed to get wallet configuration'));
  }
});

export default router; 