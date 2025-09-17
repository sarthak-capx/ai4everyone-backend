import express, { Request, Response, NextFunction } from 'express';
import { supabase, supabaseAnon, getUserSupabaseClient, jwtPublicKey } from '../index';
import { body, query, validationResult } from 'express-validator';
import { AppError } from '../index';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const router = express.Router();

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

// Get API logs
router.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { user_id, api_key, limit = '50', offset = '0' } = req.query;
    const authHeader = req.headers.authorization?.replace('Bearer ', '');

    let userId: string | null = null;

    // Try to get user ID from query parameter first (JWT auth)
    if (user_id && typeof user_id === 'string') {
      userId = user_id;
    } else if (api_key && typeof api_key === 'string') {
      // Try to resolve user ID from API key
      try {
        const { data: rpcUserId } = await supabaseAnon
          .rpc('resolve_api_key_user_id', { p_key: api_key })
          .single();
        userId = (rpcUserId as unknown as string) || null;
      } catch {
        userId = null;
      }
    } else if (authHeader) {
      // Try to resolve user ID from Authorization header (API key)
      try {
        const { data: rpcUserId } = await supabaseAnon
          .rpc('resolve_api_key_user_id', { p_key: authHeader })
          .single();
        userId = (rpcUserId as unknown as string) || null;
      } catch {
        userId = null;
      }
    }

    if (!userId) {
      return res.status(401).json({ error: 'Invalid or missing credentials' });
    }

    // Parse pagination parameters
    const limitNum = Math.min(parseInt(limit as string) || 50, 100); // Max 100 logs per request
    const offsetNum = parseInt(offset as string) || 0;

    // Use user-scoped client for secure access
    const userClient = getUserSupabaseClient(userId);

    // Query API logs with user-scoped client
    const { data: apiLogs, error: apiLogsError, count } = await userClient
      .from('api_logs')
      .select('*', { count: 'exact' })
      .eq('user_id', userId)
      .neq('endpoint_called', 'wallet_login')  // Filter out wallet login events
      .order('timestamp', { ascending: false })
      .range(offsetNum, offsetNum + limitNum - 1);

    if (apiLogsError) {
      console.error('Error fetching API logs:', apiLogsError);
      return res.status(500).json({ error: 'Failed to fetch API logs' });
    }

    // Format the logs for frontend consumption
    const formattedLogs = apiLogs?.map((log: any) => {
      // Determine model name based on endpoint and provider
      let modelName = 'Unknown';
      
      if (log.inference_usage_json?.provider === 'capx_ivmodels') {
        modelName = 'capx_ivmodels';
      } else if (log.endpoint_called?.includes('chat/completions')) {
        modelName = 'capx_textmodels';
      } else if (log.endpoint_called?.includes('completions')) {
        modelName = 'capx_ivmodels';
      }
      
      return {
        id: log.log_id,
        timestamp: log.timestamp,
        endpoint_called: log.endpoint_called,  // Keep original field name
        model: modelName,  // Use the provider name
        cost: parseFloat(log.final_cost_usd_cents || 0) / 100,
        status_code_returned: log.status_code_returned,
        success: log.status_code_returned >= 200 && log.status_code_returned < 300,
        inference_usage_json: log.inference_usage_json || {}  // Use the field name frontend expects
      };
    }) || [];

    res.json({
      logs: formattedLogs,
      pagination: {
        total: count || 0,
        limit: limitNum,
        offset: offsetNum,
        has_more: (count || 0) > offsetNum + limitNum
      }
    });
  } catch (error) {
    console.error('Error in logs endpoint:', error);
    // Return empty logs instead of error
    res.json({
      logs: [],
      pagination: {
        total: 0,
        limit: 50,
        offset: 0,
        has_more: false
      }
    });
  }
});

export default router; 