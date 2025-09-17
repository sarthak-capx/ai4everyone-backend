-- Secure Payment Verification with Idempotency
-- This migration fixes the race condition in payment verification

-- Create payment_attempts table for idempotency
CREATE TABLE IF NOT EXISTS payment_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    idempotency_key TEXT UNIQUE NOT NULL,
    tx_hash TEXT NOT NULL,
    chain_id INTEGER NOT NULL,
    user_id UUID NOT NULL REFERENCES profiles(id),
    amount_usd NUMERIC(10,2) NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed', 'invalid')),
    blockchain_data JSONB,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_payment_attempts_idempotency_key ON payment_attempts(idempotency_key);
CREATE INDEX IF NOT EXISTS idx_payment_attempts_tx_hash ON payment_attempts(tx_hash);
CREATE INDEX IF NOT EXISTS idx_payment_attempts_user_id ON payment_attempts(user_id);
CREATE INDEX IF NOT EXISTS idx_payment_attempts_status ON payment_attempts(status);
CREATE INDEX IF NOT EXISTS idx_payment_attempts_created_at ON payment_attempts(created_at);

-- Function to insert payment attempt atomically
CREATE OR REPLACE FUNCTION insert_payment_attempt(
    p_idempotency_key TEXT,
    p_tx_hash TEXT,
    p_chain_id INTEGER,
    p_user_id UUID,
    p_amount NUMERIC,
    p_status TEXT DEFAULT 'pending'
) RETURNS JSON AS $$
DECLARE
    existing_attempt payment_attempts%ROWTYPE;
    error_id UUID;
BEGIN
    -- Check if payment attempt already exists
    SELECT * INTO existing_attempt 
    FROM payment_attempts 
    WHERE idempotency_key = p_idempotency_key;
    
    IF FOUND THEN
        -- Return existing attempt status
        RETURN json_build_object(
            'success', false,
            'error', 'Payment attempt already exists',
            'status', existing_attempt.status,
            'attempt_id', existing_attempt.id
        );
    END IF;
    
    -- Check if transaction hash already processed
    SELECT * INTO existing_attempt 
    FROM payment_attempts 
    WHERE tx_hash = p_tx_hash AND status = 'completed';
    
    IF FOUND THEN
        RETURN json_build_object(
            'success', false,
            'error', 'Transaction already processed',
            'status', 'completed'
        );
    END IF;
    
    -- Insert new payment attempt
    INSERT INTO payment_attempts (
        idempotency_key,
        tx_hash,
        chain_id,
        user_id,
        amount_usd,
        status
    ) VALUES (
        p_idempotency_key,
        p_tx_hash,
        p_chain_id,
        p_user_id,
        p_amount,
        p_status
    );
    
    RETURN json_build_object(
        'success', true,
        'attempt_id', gen_random_uuid()
    );
    
EXCEPTION
    WHEN unique_violation THEN
        -- Handle race condition where another request inserted the same idempotency key
        SELECT * INTO existing_attempt 
        FROM payment_attempts 
        WHERE idempotency_key = p_idempotency_key;
        
        RETURN json_build_object(
            'success', false,
            'error', 'Payment attempt already exists',
            'status', existing_attempt.status,
            'attempt_id', existing_attempt.id
        );
        
    WHEN OTHERS THEN
        -- Log error internally
        error_id := gen_random_uuid();
        INSERT INTO error_logs (
            id,
            function_name,
            error_state,
            error_message,
            error_detail,
            user_id,
            occurred_at
        ) VALUES (
            error_id,
            'insert_payment_attempt',
            SQLSTATE,
            SQLERRM,
            COALESCE(NULLIF(current_setting('log_error_verbosity'), 'default'), 'terse'),
            p_user_id,
            NOW()
        );
        
        RETURN json_build_object(
            'success', false,
            'error', 'Failed to process payment attempt',
            'error_id', error_id
        );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to complete payment attempt
CREATE OR REPLACE FUNCTION complete_payment_attempt(
    p_idempotency_key TEXT,
    p_status TEXT,
    p_blockchain_data JSONB DEFAULT NULL,
    p_error_message TEXT DEFAULT NULL
) RETURNS JSON AS $$
DECLARE
    attempt_id UUID;
    error_id UUID;
BEGIN
    -- Update payment attempt status
    UPDATE payment_attempts 
    SET 
        status = p_status,
        blockchain_data = p_blockchain_data,
        error_message = p_error_message,
        updated_at = NOW()
    WHERE idempotency_key = p_idempotency_key
    RETURNING id INTO attempt_id;
    
    IF NOT FOUND THEN
        RETURN json_build_object(
            'success', false,
            'error', 'Payment attempt not found'
        );
    END IF;
    
    RETURN json_build_object(
        'success', true,
        'attempt_id', attempt_id
    );
    
EXCEPTION
    WHEN OTHERS THEN
        -- Log error internally
        error_id := gen_random_uuid();
        INSERT INTO error_logs (
            id,
            function_name,
            error_state,
            error_message,
            error_detail,
            occurred_at
        ) VALUES (
            error_id,
            'complete_payment_attempt',
            SQLSTATE,
            SQLERRM,
            COALESCE(NULLIF(current_setting('log_error_verbosity'), 'default'), 'terse'),
            NOW()
        );
        
        RETURN json_build_object(
            'success', false,
            'error', 'Failed to complete payment attempt',
            'error_id', error_id
        );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get payment attempt status
CREATE OR REPLACE FUNCTION get_payment_attempt_status(
    p_idempotency_key TEXT
) RETURNS JSON AS $$
DECLARE
    attempt payment_attempts%ROWTYPE;
BEGIN
    SELECT * INTO attempt 
    FROM payment_attempts 
    WHERE idempotency_key = p_idempotency_key;
    
    IF NOT FOUND THEN
        RETURN json_build_object(
            'success', false,
            'error', 'Payment attempt not found'
        );
    END IF;
    
    RETURN json_build_object(
        'success', true,
        'status', attempt.status,
        'attempt_id', attempt.id,
        'created_at', attempt.created_at,
        'updated_at', attempt.updated_at
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant permissions
GRANT EXECUTE ON FUNCTION insert_payment_attempt TO anon;
GRANT EXECUTE ON FUNCTION complete_payment_attempt TO anon;
GRANT EXECUTE ON FUNCTION get_payment_attempt_status TO anon;

-- Add RLS policies for payment_attempts table
ALTER TABLE payment_attempts ENABLE ROW LEVEL SECURITY;

-- Users can only see their own payment attempts
CREATE POLICY "Users can view their own payment attempts" ON payment_attempts
    FOR SELECT USING (auth.uid() = user_id);

-- Only the application can insert/update payment attempts
CREATE POLICY "Application can manage payment attempts" ON payment_attempts
    FOR ALL USING (auth.role() = 'service_role');

-- Clean up old payment attempts (keep for 30 days)
CREATE OR REPLACE FUNCTION cleanup_old_payment_attempts() RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM payment_attempts 
    WHERE created_at < NOW() - INTERVAL '30 days'
    AND status IN ('completed', 'failed', 'invalid');
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant cleanup function permission
GRANT EXECUTE ON FUNCTION cleanup_old_payment_attempts TO service_role;
