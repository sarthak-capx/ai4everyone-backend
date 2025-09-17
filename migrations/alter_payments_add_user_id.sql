ALTER TABLE IF EXISTS payments
  ADD COLUMN IF NOT EXISTS user_id TEXT;

CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id); 