-- Atomic Balance Update Functions
-- Prevents race conditions in balance updates

-- Function to atomically deduct balance with proper locking
CREATE OR REPLACE FUNCTION deduct_balance_atomic(
  p_user_id UUID,
  p_amount_cents INTEGER
) RETURNS JSON AS $$
DECLARE
  current_balance INTEGER;
  new_balance INTEGER;
  result JSON;
BEGIN
  -- Lock the user's profile row for update to prevent race conditions
  SELECT balance_usd_cents INTO current_balance
  FROM profiles 
  WHERE id = p_user_id
  FOR UPDATE;
  
  -- Check if user exists
  IF NOT FOUND THEN
    RETURN json_build_object(
      'success', false,
      'error', 'User not found',
      'new_balance', null
    );
  END IF;
  
  -- Check if sufficient balance
  IF current_balance < p_amount_cents THEN
    RETURN json_build_object(
      'success', false,
      'error', 'Insufficient balance',
      'current_balance', current_balance,
      'required_amount', p_amount_cents,
      'new_balance', current_balance
    );
  END IF;
  
  -- Calculate new balance
  new_balance := current_balance - p_amount_cents;
  
  -- Update balance atomically
  UPDATE profiles 
  SET 
    balance_usd_cents = new_balance,
    updated_at = NOW()
  WHERE id = p_user_id;
  
  -- Return success with new balance
  RETURN json_build_object(
    'success', true,
    'error', null,
    'old_balance', current_balance,
    'new_balance', new_balance,
    'amount_deducted', p_amount_cents
  );
  
EXCEPTION
  WHEN OTHERS THEN
    -- Rollback and return error
    RETURN json_build_object(
      'success', false,
      'error', SQLERRM,
      'new_balance', null
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to atomically add balance (for payments)
CREATE OR REPLACE FUNCTION add_balance_atomic(
  p_user_id UUID,
  p_amount_cents INTEGER
) RETURNS JSON AS $$
DECLARE
  current_balance INTEGER;
  new_balance INTEGER;
  result JSON;
BEGIN
  -- Lock the user's profile row for update to prevent race conditions
  SELECT balance_usd_cents INTO current_balance
  FROM profiles 
  WHERE id = p_user_id
  FOR UPDATE;
  
  -- Check if user exists
  IF NOT FOUND THEN
    RETURN json_build_object(
      'success', false,
      'error', 'User not found',
      'new_balance', null
    );
  END IF;
  
  -- Calculate new balance
  new_balance := current_balance + p_amount_cents;
  
  -- Update balance atomically
  UPDATE profiles 
  SET 
    balance_usd_cents = new_balance,
    updated_at = NOW()
  WHERE id = p_user_id;
  
  -- Return success with new balance
  RETURN json_build_object(
    'success', true,
    'error', null,
    'old_balance', current_balance,
    'new_balance', new_balance,
    'amount_added', p_amount_cents
  );
  
EXCEPTION
  WHEN OTHERS THEN
    -- Rollback and return error
    RETURN json_build_object(
      'success', false,
      'error', SQLERRM,
      'new_balance', null
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute permissions to authenticated users
GRANT EXECUTE ON FUNCTION deduct_balance_atomic(UUID, INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION add_balance_atomic(UUID, INTEGER) TO authenticated;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_profiles_id_balance ON profiles(id, balance_usd_cents);

-- Add comments for documentation
COMMENT ON FUNCTION deduct_balance_atomic(UUID, INTEGER) IS 'Atomically deduct balance from user account with row-level locking to prevent race conditions';
COMMENT ON FUNCTION add_balance_atomic(UUID, INTEGER) IS 'Atomically add balance to user account with row-level locking to prevent race conditions'; 