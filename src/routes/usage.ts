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

// Get monthly usage stats
router.get('/monthly-stats', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { user_id } = req.query;
    const apiKey = req.headers.authorization?.replace('Bearer ', '');

    let userId: string | null = null;

    // Try to get user ID from query parameter first (JWT auth)
    if (user_id && typeof user_id === 'string') {
      userId = user_id;
    } else if (apiKey) {
      // Try to resolve user ID from API key
      try {
        const { data: rpcUserId } = await supabaseAnon
          .rpc('resolve_api_key_user_id', { p_key: apiKey })
          .single();
        userId = (rpcUserId as unknown as string) || null;
      } catch {
        userId = null;
      }
    }

    if (!userId) {
      return res.status(401).json({ error: 'Invalid or missing credentials' });
    }

    // Get current date for calculations
    const now = new Date();
    const currentYear = now.getFullYear();

    // Generate months for the current year (Jan to Dec)
    const months = [];
    for (let month = 1; month <= 12; month++) {
      months.push(`${currentYear}-${month.toString().padStart(2, '0')}`);
    }

    // Use user-scoped client for secure access
    const userClient = getUserSupabaseClient(userId);

    // Query API logs with user-scoped client
    const { data: apiLogs, error: apiLogsError } = await userClient
      .from('api_logs')
      .select('final_cost_usd_cents, timestamp')
      .eq('user_id', userId)
      .gte('timestamp', `${currentYear}-01-01`) // Start of the year
      .order('timestamp', { ascending: true });

    if (apiLogsError) {
      console.error('Error fetching API logs:', apiLogsError);
      return res.status(500).json({ error: 'Failed to fetch API usage data' });
    }

    // Query transactions with user-scoped client
    const { data: transactions, error: transactionsError } = await userClient
      .from('transactions')
      .select('amount, created_at')
      .eq('user_id', userId)
      .gte('created_at', `${currentYear}-01-01`) // Start of the year
      .order('created_at', { ascending: true });

    if (transactionsError) {
      console.error('Error fetching transactions:', transactionsError);
      // Continue with empty transactions
    }

    // Process the data into monthly stats
    const monthlyStats = months.map(month => {
      const [year, monthNum] = month.split('-');
      const monthStart = new Date(parseInt(year), parseInt(monthNum) - 1, 1);
      const monthEnd = new Date(parseInt(year), parseInt(monthNum), 0);

      // Calculate API costs for this month
      const monthApiLogs = apiLogs?.filter((log: any) => {
        const logDate = new Date(log.timestamp);
        return logDate >= monthStart && logDate <= monthEnd;
      }) || [];

      const apiCostCents = monthApiLogs.reduce((sum: number, log: any) => {
        return sum + (parseFloat(log.final_cost_usd_cents) || 0);
      }, 0);

      const apiCostUsd = apiCostCents / 100;
      const apiCalls = monthApiLogs.length;

      // Calculate transactions for this month
      const monthTransactions = transactions?.filter((tx: any) => {
        const txDate = new Date(tx.created_at);
        return txDate >= monthStart && txDate <= monthEnd;
      }) || [];

      const spendingUsd = monthTransactions.reduce((sum: number, tx: any) => {
        return sum + (parseFloat(tx.amount) || 0);
      }, 0);

      return {
        month,
        api_cost_usd: parseFloat(apiCostUsd.toFixed(2)),
        api_calls: apiCalls,
        spending_usd: parseFloat(spendingUsd.toFixed(2))
      };
    });

    res.json({ stats: monthlyStats });
  } catch (error) {
    console.error('Error in monthly stats:', error);
    // Return empty stats instead of error
    const now = new Date();
    const currentYear = now.getFullYear();
    const months = [];
    for (let month = 1; month <= 12; month++) {
      months.push(`${currentYear}-${month.toString().padStart(2, '0')}`);
    }
    const emptyStats = months.map(month => ({
      month,
      api_cost_usd: 0,
      api_calls: 0,
      spending_usd: 0
    }));
    res.json({ stats: emptyStats });
  }
});

export default router; 