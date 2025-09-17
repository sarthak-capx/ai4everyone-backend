import express, { Request, Response, NextFunction } from 'express';
import { supabase, supabaseAnon, getUserSupabaseClient, jwtPublicKey } from '../index';
import { v4 as uuidv4 } from 'uuid';
import { body, query, param, validationResult } from 'express-validator';
import crypto from 'crypto';
import { AppError } from '../index';
import jwt from 'jsonwebtoken';
import { 
  generateSecureApiKey, 
  createApiKeyMetadata, 
  sanitizeApiKeyData,
  isValidApiKeyFormat,
  extractApiKeyPrefix
} from '../utils/secureApiKeys';

const router = express.Router();

// Middleware to get user_email from request (expects ?user_email=... in query)
function getUserEmail(req: Request): string | null {
  return req.query.user_email as string || null;
}

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

// GET /api-keys - fetch all API keys for the authenticated user
router.get('/', authenticateUser, async (req: Request, res: Response) => {
  const user_id = (req as any).user.sub; // From authenticated token (sub claim)
  
  try {
    // Use user-scoped client for secure access
    const userClient = getUserSupabaseClient(user_id);
    
    // Use direct table query since the view has RLS issues
    const { data, error } = await userClient
      .from('api_keys')
      .select('id, user_id, user_email, name, key_prefix, created_at, is_active, last_used_at, expires_at')
      .eq('user_id', user_id)
      .eq('is_active', true)
      .order('created_at', { ascending: false });
      
    if (error) {
      console.error('Error fetching API keys:', error);
      return res.status(500).json({ error: 'Failed to fetch API keys' });
    }
    
    // Return sanitized data (no sensitive fields)
    res.json(data);
  } catch (err) {
    console.error('Unexpected error in GET /api-keys:', err);
    res.status(500).json({ error: 'Unexpected server error' });
  }
});

// POST /api-keys - create a new API key for the authenticated user
router.post('/', authenticateUser, [
  body('name')
    .isString()
    .isLength({ min: 1, max: 100 }).withMessage('Name is required (1-100 chars)')
    .matches(/^[a-zA-Z0-9]+$/).withMessage('Name must contain only letters and numbers (no special characters)'),
], async (req: Request, res: Response) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const user_id = (req as any).user.sub; // From authenticated token (sub claim)
  const user_email = (req as any).user.email;
  const { name, replace_existing } = req.body;
  
  if (!name) return res.status(400).json({ error: 'Missing name' });
  
  try {
    // Use user-scoped client for secure access
    const userClient = getUserSupabaseClient(user_id);
    
    // Fetch existing ACTIVE keys for this user
    const { data: existingKeys, error: fetchKeysError } = await userClient
      .from('api_keys')
      .select('id')
      .eq('user_id', user_id)
      .eq('is_active', true);
      
    if (fetchKeysError) {
      console.error('Error fetching existing API keys:', fetchKeysError);
      return res.status(500).json({ error: 'Failed to fetch existing API keys' });
    }
    
    if (existingKeys && existingKeys.length >= 5 && !replace_existing) {
      return res.status(400).json({ error: 'Maximum 5 API keys per user' });
    }
    
    // Only delete all keys if explicitly requested
    if (replace_existing) {
      const { error: deleteError } = await userClient
        .from('api_keys')
        .delete()
        .eq('user_id', user_id);
        
      if (deleteError) {
        console.error('Error deleting old API keys:', deleteError);
        return res.status(500).json({ error: 'Failed to delete old API keys' });
      }
    }
    
    // Generate secure API key with metadata
    const { metadata, secureKey } = await createApiKeyMetadata(user_id, user_email, name);
    
    // Insert the new API key using user-scoped client (NO PLAINTEXT STORAGE)
    const { data, error } = await userClient
      .from('api_keys')
      .insert([{ 
        id: uuidv4(), 
        ...metadata
        // ✅ SECURE: No plaintext storage - only hash, prefix, checksum, salt
      }])
      .select()
      .single();
      
    if (error) {
      console.error('Error inserting API key:', error);
      return res.status(500).json({ error: 'Failed to create API key' });
    }
    
    // ✅ SECURE: Return plaintext only once, never stored in database
    res.status(201).json({ 
      ...sanitizeApiKeyData(data as any), 
      key: secureKey.plaintext  // Return plaintext only once for user to copy
    });
  } catch (err) {
    console.error('Unexpected error in POST /api-keys:', err);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// DELETE /api-keys/:id - delete an API key by id for the authenticated user
router.delete('/:id', authenticateUser, [
  param('id').isUUID().withMessage('Valid API key id is required'),
], async (req: Request, res: Response) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const user_id = (req as any).user.sub; // From authenticated token (sub claim)
  const { id } = req.params;
  
  if (!id) return res.status(400).json({ error: 'Missing id' });
  
  try {
    // Use user-scoped client for secure access
    const userClient = getUserSupabaseClient(user_id);
    
    // Soft delete: set is_active to false instead of hard delete
    const { data, error, count } = await userClient
      .from('api_keys')
      .update({ is_active: false })
      .match({ id: id, user_id: user_id })
      .select();
      
    if (error) {
      console.error('Error deactivating API key:', error);
      return res.status(500).json({ error: 'Failed to deactivate API key' });
    }
    
    if (count === 0) {
      return res.status(404).json({ error: 'API key not found or unauthorized' });
    }
    
    // Audit the security event
    await supabaseAnon.rpc('audit_security_event', {
      p_event_type: 'api_key_deactivated',
      p_user_id: user_id,
      p_details: { key_id: id }
    });
    
    res.status(204).end();
  } catch (err) {
    console.error('Unexpected error in DELETE /api-keys/:id:', err);
    res.status(500).json({ error: 'An error occurred' });
  }
});

export default router; 