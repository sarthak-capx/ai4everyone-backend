-- Migration: Encrypt API Keys Storage
-- Date: 2025-08-20
-- Description: Update api_keys table to store hashed keys instead of plaintext

-- Step 1: Add new columns for encrypted storage
ALTER TABLE api_keys 
ADD COLUMN IF NOT EXISTS key_hash TEXT,
ADD COLUMN IF NOT EXISTS key_prefix VARCHAR(12),
ADD COLUMN IF NOT EXISTS key_checksum VARCHAR(8),
ADD COLUMN IF NOT EXISTS key_salt TEXT,
ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true,
ADD COLUMN IF NOT EXISTS allowed_ips TEXT[],
ADD COLUMN IF NOT EXISTS rate_limit_override INTEGER;

-- Step 2: Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_active ON api_keys(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires ON api_keys(expires_at);

-- Step 3: Add constraints
ALTER TABLE api_keys 
ADD CONSTRAINT IF NOT EXISTS chk_api_keys_prefix_format 
CHECK (key_prefix ~ '^capx_[A-Za-z0-9_-]{7}$'),
ADD CONSTRAINT IF NOT EXISTS chk_api_keys_checksum_format 
CHECK (key_checksum ~ '^[a-f0-9]{8}$'),
ADD CONSTRAINT IF NOT EXISTS chk_api_keys_expires_future 
CHECK (expires_at IS NULL OR expires_at > NOW());

-- Step 4: Create function to validate API key format
CREATE OR REPLACE FUNCTION validate_api_key_format(p_key TEXT)
RETURNS BOOLEAN AS $$
BEGIN
  RETURN p_key ~ '^capx_[A-Za-z0-9_-]{43,}$';
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Step 5: Create function to get user ID from API key (for proxy routes)
CREATE OR REPLACE FUNCTION get_user_id_from_api_key(p_api_key TEXT)
RETURNS UUID AS $$
DECLARE
  user_id UUID;
  key_prefix VARCHAR(12);
BEGIN
  -- Extract prefix from API key
  key_prefix := substring(p_api_key from 1 for 12);
  
  -- Find matching API key by prefix
  SELECT ak.user_id INTO user_id
  FROM api_keys ak
  WHERE ak.key_prefix = key_prefix
    AND ak.is_active = true
    AND (ak.expires_at IS NULL OR ak.expires_at > NOW());
  
  RETURN user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Step 6: Create function to validate API key and update last_used
CREATE OR REPLACE FUNCTION validate_and_update_api_key(
  p_api_key TEXT,
  p_user_ip INET DEFAULT NULL
)
RETURNS JSON AS $$
DECLARE
  key_record RECORD;
  result JSON;
BEGIN
  -- Extract prefix and find key record
  SELECT * INTO key_record
  FROM api_keys
  WHERE key_prefix = substring(p_api_key from 1 for 12)
    AND is_active = true
    AND (expires_at IS NULL OR expires_at > NOW());
  
  IF NOT FOUND THEN
    RETURN json_build_object(
      'valid', false,
      'error', 'API key not found or inactive'
    );
  END IF;
  
  -- Check IP restrictions if configured
  IF key_record.allowed_ips IS NOT NULL AND p_user_ip IS NOT NULL THEN
    IF NOT (p_user_ip::text = ANY(key_record.allowed_ips)) THEN
      RETURN json_build_object(
        'valid', false,
        'error', 'IP address not allowed'
      );
    END IF;
  END IF;
  
  -- Note: Actual hash verification will be done in application code
  -- This function only checks metadata and updates usage
  
  -- Update last_used_at
  UPDATE api_keys 
  SET last_used_at = NOW()
  WHERE id = key_record.id;
  
  RETURN json_build_object(
    'valid', true,
    'user_id', key_record.user_id,
    'rate_limit_override', key_record.rate_limit_override
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Step 7: Create RLS policies for secure access
DROP POLICY IF EXISTS "Users can view own api_keys" ON api_keys;
DROP POLICY IF EXISTS "Users can insert own api_keys" ON api_keys;
DROP POLICY IF EXISTS "Users can update own api_keys" ON api_keys;
DROP POLICY IF EXISTS "Users can delete own api_keys" ON api_keys;

-- View policy (users can only see their own keys, without sensitive data)
CREATE POLICY "Users can view own api_keys" ON api_keys
  FOR SELECT USING (
    auth.uid() = user_id
  );

-- Insert policy (users can create keys for themselves)
CREATE POLICY "Users can insert own api_keys" ON api_keys
  FOR INSERT WITH CHECK (
    auth.uid() = user_id
  );

-- Update policy (users can update their own keys)
CREATE POLICY "Users can update own api_keys" ON api_keys
  FOR UPDATE USING (
    auth.uid() = user_id
  );

-- Delete policy (users can delete their own keys)
CREATE POLICY "Users can delete own api_keys" ON api_keys
  FOR DELETE USING (
    auth.uid() = user_id
  );

-- Step 8: Create view for safe API key listing (excludes sensitive data)
CREATE OR REPLACE VIEW user_api_keys_safe AS
SELECT 
  id,
  user_id,
  user_email,
  name,
  key_prefix,
  key_checksum,
  created_at,
  last_used_at,
  expires_at,
  is_active,
  allowed_ips,
  rate_limit_override
FROM api_keys
WHERE auth.uid() = user_id;

-- Step 9: Grant permissions
GRANT SELECT ON user_api_keys_safe TO authenticated;
GRANT EXECUTE ON FUNCTION get_user_id_from_api_key(TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION validate_and_update_api_key(TEXT, INET) TO authenticated;

-- Step 10: Add comments for documentation
COMMENT ON TABLE api_keys IS 'API keys with encrypted storage - plaintext keys are never stored';
COMMENT ON COLUMN api_keys.key_hash IS 'Argon2id hash of the API key - never store plaintext';
COMMENT ON COLUMN api_keys.key_prefix IS 'First 12 characters for quick lookup';
COMMENT ON COLUMN api_keys.key_checksum IS 'SHA256 checksum for validation';
COMMENT ON COLUMN api_keys.key_salt IS 'Salt used for Argon2id hashing';
COMMENT ON COLUMN api_keys.last_used_at IS 'Timestamp of last API key usage';
COMMENT ON COLUMN api_keys.expires_at IS 'Expiration timestamp for key rotation';
COMMENT ON COLUMN api_keys.is_active IS 'Whether the key is active';
COMMENT ON COLUMN api_keys.allowed_ips IS 'IP address restrictions (optional)';
COMMENT ON COLUMN api_keys.rate_limit_override IS 'Custom rate limit for this key (optional)';
