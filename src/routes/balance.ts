import express, { Request, Response, NextFunction } from 'express';
import { supabase, supabaseAnon, getUserSupabaseClient, jwtPublicKey } from '../index';
import { body, query, validationResult } from 'express-validator';
import { AppError } from '../index';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const router = express.Router();

// Helper: check if string is a valid Ethereum address
function isEthereumAddress(str: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(str);
}

// Custom validator for user_email or wallet address
function isEmailOrEthAddress(value: string) {
  if (typeof value !== 'string') return false;
  // Accept if valid email or valid Ethereum address
  return isEthereumAddress(value) || /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value);
}

// JWT authentication middleware with RSA verification
const authenticateUser = (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  
  try {
    // Use pre-validated public key from index.ts
    if (!jwtPublicKey) {
      return res.status(500).json({ error: 'JWT public key not configured' });
    }
    
    const decoded = jwt.verify(token, jwtPublicKey, { 
      algorithms: ['RS256'],
      issuer: 'https://api.ai4everyone.com',
      audience: 'ai4everyone-api'
    });
    
    // ✅ SECURE: Device fingerprint verification moved to session-based validation
    // The fingerprint is now stored in the session, not in the JWT
    // This provides better security as session data is server-side only
    
    (req as any).user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Admin check middleware (for demo, checks isAdmin property in JWT)
const authenticateAdmin = (req: Request, res: Response, next: NextFunction) => {
  authenticateUser(req, res, () => {
    if (!(req as any).user.isAdmin) {
      return res.status(403).json({ error: 'Admin privileges required' });
    }
    next();
  });
};

// Get user's balance
router.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return next(new AppError(401, 'Authentication required'));
    }

    // Support either JWT or API key in Authorization header
    const token = authHeader.replace('Bearer ', '');

    let user_id: string | null = null;

    // Try JWT first
    try {
      if (!jwtPublicKey) {
        throw new Error('JWT public key not configured');
      }
      const decoded = jwt.verify(token, jwtPublicKey, { 
        algorithms: ['RS256'],
        issuer: 'https://api.ai4everyone.com',
        audience: 'ai4everyone-api'
      }) as any;
      user_id = decoded?.sub || null; // Use 'sub' claim instead of 'id'
    } catch (e) {
      // Not a valid JWT: treat as API key and resolve user_id via SECURITY DEFINER RPC only
      try {
        const { data: rpcUserId } = await supabaseAnon
          .rpc('resolve_api_key_user_id', { p_key: token })
          .single();
        user_id = (rpcUserId as unknown as string) || null;
      } catch {
        user_id = null;
      }
    }

    if (!user_id) {
      return next(new AppError(401, 'Invalid or missing credentials'));
    }

    // Use SECURITY DEFINER function to get user profile
    const { data: profile, error } = await supabaseAnon
      .rpc('get_user_profile', { p_user_id: user_id });

    if (error) {
      console.error('Error fetching user profile:', error);
      return next(new AppError(500, 'Error fetching balance'));
    }
    if (!profile) {
      return next(new AppError(404, 'User profile not found'));
    }

    // Convert cents to dollars for display
    const balance = Math.floor((profile.balance_usd_cents / 100) * 100) / 100;
    res.json({ balance, balance_usd_cents: profile.balance_usd_cents });
  } catch (err) {
    next(err);
  }
});

// Update user's balance (for adding credits)
router.post('/add', authenticateAdmin, [
  body('user_id').isString().withMessage('user_id is required'),
  body('amount_usd').isNumeric().custom((v) => v > 0).withMessage('amount_usd must be a positive number'),
], async (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(new AppError(400, 'Validation failed'));
  }
  try {
    const { user_id, amount_usd } = req.body;
    if (!user_id || !amount_usd) {
      return next(new AppError(400, 'Missing user_id or amount'));
    }
    
    // Validate UUID format (SAFE - prevents invalid user IDs)
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(user_id)) {
      return next(new AppError(400, 'Invalid user ID format'));
    }
    
    // Convert dollars to cents for storage
    const amount_cents = Math.round(amount_usd * 100);
    
    // Use SECURITY DEFINER function to update balance atomically
    const { error: updateError } = await supabaseAnon
      .rpc('update_balance_atomic', {
        p_user_id: user_id,
        p_amount_cents: amount_cents
      });

    if (updateError) {
      console.error('Error updating balance:', updateError);
      return next(new AppError(500, 'Error updating balance'));
    }

    // Get updated balance for response
    const { data: profile, error: fetchError } = await supabaseAnon
      .rpc('get_user_profile', { p_user_id: user_id });

    if (fetchError) {
      console.error('Error fetching updated balance:', fetchError);
      return next(new AppError(500, 'Error fetching updated balance'));
    }

    // Return new balance in dollars
    const new_balance = (profile.balance_usd_cents / 100).toFixed(2);
    
    // Audit the admin action
    await supabaseAnon.rpc('audit_security_event', {
      p_event_type: 'admin_balance_added',
      p_user_id: user_id,
      p_details: { 
        amount_usd,
        amount_cents,
        admin_user_id: (req as any).user.sub
      }
    });
    
    res.json({ balance: new_balance });
  } catch (err) {
    console.error('Error in /balance/add:', err);
    next(err);
  }
});

// Get user's payment history (JWT-based)
router.get('/payment-history-jwt', authenticateUser, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req as any).user.sub;

    // Fetch payment history for this user via user-scoped client (RLS)
    const { data: transactions, error: transactionError } = await getUserSupabaseClient(userId)
      .from('transactions')
      .select('hash, amount, created_at')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (transactionError) {
      console.error('Error fetching payment history:', transactionError);
      return next(new AppError(500, 'Failed to fetch payment history'));
    }

    res.status(200).json({ transactions: transactions || [] });
  } catch (error) {
    console.error('Payment history error:', error);
    next(error);
  }
});

// Get user's payment history
router.get('/payment-history', async (req: Request, res: Response, next: NextFunction) => {
  const apiKey = req.headers.authorization?.replace('Bearer ', '');
  if (!apiKey) {
    return next(new AppError(401, 'API key required'));
  }

  try {
    // Resolve user_id from API key using SECURITY DEFINER RPC
    let userIdFromKey: string | null = null;
    try {
      const { data: rpcUserId } = await supabaseAnon
        .rpc('resolve_api_key_user_id', { p_key: apiKey })
        .single();
      if (rpcUserId) userIdFromKey = rpcUserId as unknown as string;
    } catch {}

    if (!userIdFromKey) {
      return next(new AppError(401, 'Invalid API key'));
    }

    const userId = userIdFromKey;

    // Fetch payment history for this user via user-scoped client (RLS)
    const { data: transactions, error: transactionError } = await getUserSupabaseClient(userId)
      .from('transactions')
      .select('hash, amount, created_at')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (transactionError) {
      console.error('Error fetching payment history:', transactionError);
      return next(new AppError(500, 'Failed to fetch payment history'));
    }

    res.status(200).json({ transactions: transactions || [] });
  } catch (error) {
    console.error('Payment history error:', error);
    next(error);
  }
});

export default router; 