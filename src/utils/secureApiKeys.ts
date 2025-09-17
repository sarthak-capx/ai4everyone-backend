import crypto from 'crypto';
import argon2 from 'argon2';

export interface SecureApiKey {
  plaintext: string;
  hash: string;
  prefix: string;
  checksum: string;
  salt: string;
}

export interface ApiKeyMetadata {
  id: string;
  user_id: string;
  user_email: string;
  name: string;
  key_hash: string;
  key_prefix: string;
  key_checksum: string;
  key_salt: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  is_active: boolean;
  allowed_ips: string[] | null;
  rate_limit_override: number | null;
}

/**
 * Generate a cryptographically secure API key with metadata
 */
export async function generateSecureApiKey(): Promise<SecureApiKey> {
  // Generate cryptographically secure random key
  const keyBytes = crypto.randomBytes(32);
  const plaintext = `capx_${keyBytes.toString('base64url')}`;
  
  // Generate salt for Argon2id
  const salt = crypto.randomBytes(32);
  
  // Create hash for storage using Argon2id (memory-hard, resistant to GPU attacks)
  const hash = await argon2.hash(plaintext, {
    type: argon2.argon2id,
    memoryCost: 65536, // 64MB
    timeCost: 3,       // 3 iterations
    parallelism: 4,    // 4 threads
    salt: salt
  });
  
  // Extract identifiable prefix and checksum for quick lookup
  const prefix = plaintext.substring(0, 12); // "capx_" + first 7 chars
  const checksum = crypto.createHash('sha256')
    .update(plaintext)
    .digest('hex')
    .substring(0, 8);
  
  return { 
    plaintext, 
    hash, 
    prefix, 
    checksum,
    salt: salt.toString('base64url')
  };
}

/**
 * Validate an API key against stored hash
 */
export async function validateApiKey(
  providedKey: string, 
  storedHash: string,
  storedSalt: string
): Promise<boolean> {
  try {
    // Convert salt back to buffer
    const saltBuffer = Buffer.from(storedSalt, 'base64url');
    
    // Verify hash using Argon2id
    return await argon2.verify(storedHash, providedKey);
  } catch (error) {
    console.error('API key validation error:', error);
    return false;
  }
}

/**
 * Extract prefix from API key for database lookup
 */
export function extractApiKeyPrefix(apiKey: string): string {
  if (!apiKey.startsWith('capx_')) {
    throw new Error('Invalid API key format');
  }
  return apiKey.substring(0, 12);
}

/**
 * Validate API key format
 */
export function isValidApiKeyFormat(apiKey: string): boolean {
  return /^capx_[A-Za-z0-9_-]{43,}$/.test(apiKey);
}

/**
 * Generate API key metadata for database storage
 */
export async function createApiKeyMetadata(
  userId: string,
  userEmail: string,
  name: string,
  expiresInDays: number = 90
): Promise<{ metadata: Omit<ApiKeyMetadata, 'id' | 'created_at' | 'last_used_at'>; secureKey: SecureApiKey }> {
  const secureKey = await generateSecureApiKey();
  const expiresAt = new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000);
  
  const metadata: Omit<ApiKeyMetadata, 'id' | 'created_at' | 'last_used_at'> = {
    user_id: userId,
    user_email: userEmail,
    name,
    key_hash: secureKey.hash,
    key_prefix: secureKey.prefix,
    key_checksum: secureKey.checksum,
    key_salt: secureKey.salt,
    expires_at: expiresAt.toISOString(),
    is_active: true,
    allowed_ips: null,
    rate_limit_override: null
  };
  
  return { metadata, secureKey };
}

/**
 * Sanitize API key data for response (remove sensitive fields)
 */
export function sanitizeApiKeyData(data: ApiKeyMetadata): Omit<ApiKeyMetadata, 'key_hash' | 'key_salt'> {
  const { key_hash, key_salt, ...sanitized } = data;
  return sanitized;
}
