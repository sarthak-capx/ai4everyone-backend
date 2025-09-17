-- Migration: Remove Plaintext API Keys Column
-- Date: 2025-01-18
-- Description: Remove the 'key' column that stores plaintext API keys for security

-- Step 1: Verify we have the encrypted columns in place
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'api_keys' AND column_name = 'key_hash'
  ) THEN
    RAISE EXCEPTION 'Encrypted columns not found. Run encrypted_api_keys.sql migration first.';
  END IF;
END $$;

-- Step 2: Nullify any remaining plaintext data (safety measure)
UPDATE api_keys SET key = NULL WHERE key IS NOT NULL;

-- Step 3: Remove the plaintext 'key' column
ALTER TABLE api_keys DROP COLUMN IF EXISTS key;

-- Step 4: Add comment to document the security improvement
COMMENT ON TABLE api_keys IS 'API keys with encrypted storage - NO plaintext keys stored (security hardened)';

-- Step 5: Verify the change
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'api_keys' AND column_name = 'key'
  ) THEN
    RAISE EXCEPTION 'Plaintext key column still exists after removal attempt.';
  END IF;
  
  RAISE NOTICE '✅ Successfully removed plaintext API key column. Security improved.';
END $$;
