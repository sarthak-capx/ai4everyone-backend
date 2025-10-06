-- AI4Everyone Minimal Schema (public)
-- Purpose: Recreate the DB structures actually used by the application
-- Scope: profiles, api_keys, api_logs, payments, transactions, security_audit
-- Functions: upsert_profile_for_wallet, audit_security_event, get_user_profile,
--            add_balance_atomic, deduct_balance_atomic, resolve_api_key_user_id
-- Notes:
-- - Enable required extensions before running: pgcrypto (for gen_random_uuid)
-- - Adjust grants/RLS as needed for your environment

-- ===== Extensions =====
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()

-- ===== Tables =====

-- profiles: core user profile and balance
CREATE TABLE IF NOT EXISTS public.profiles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text,
  email text UNIQUE,
  wallet_address text,
  api_key_hash text,
  api_key_prefix text,
  balance_usd_cents numeric,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);
CREATE INDEX IF NOT EXISTS idx_profiles_wallet ON public.profiles(email) WHERE email LIKE '%@wallet.local';
CREATE INDEX IF NOT EXISTS idx_profiles_wallet_address ON public.profiles(wallet_address);
CREATE INDEX IF NOT EXISTS idx_profiles_id_balance ON public.profiles(id, balance_usd_cents);

-- api_keys: hashed storage (no plaintext)
CREATE TABLE IF NOT EXISTS public.api_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES public.profiles(id) ON DELETE CASCADE,
  user_email text,
  name text,
  key_hash text,
  key_prefix varchar(12),
  key_checksum varchar(8),
  key_salt text,
  last_used_at timestamptz,
  expires_at timestamptz,
  is_active boolean DEFAULT true,
  allowed_ips text[],
  rate_limit_override integer,
  created_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON public.api_keys(user_id);

-- api_logs: request/usage logs per user
CREATE TABLE IF NOT EXISTS public.api_logs (
  log_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.profiles(id),
  user_email text,
  api_key_prefix_used text,
  timestamp timestamptz DEFAULT now(),
  endpoint_called text,
  inference_usage_json jsonb,
  inference_cost_usd numeric,
  markup_percentage bigint,
  final_cost_usd_cents numeric,
  status_code_returned bigint,
  was_deducted boolean
);

CREATE INDEX IF NOT EXISTS idx_api_logs_user_id ON public.api_logs(user_id);

-- payments: off-chain record of wallet deposits credited to balance
CREATE TABLE IF NOT EXISTS public.payments (
  receipt_id text PRIMARY KEY,
  user_id text,
  user_address text NOT NULL,
  network text NOT NULL,
  chain_id integer NOT NULL,
  token_symbol text NOT NULL,
  token_address text NOT NULL,
  token_decimals integer NOT NULL,
  amount_usd numeric(10,2) NOT NULL,
  amount_wei text NOT NULL,
  timestamp bigint NOT NULL,
  signature text NOT NULL,
  status text CHECK (status IN ('pending','completed')) DEFAULT 'pending',
  tx_hash text,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_payments_user_id ON public.payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_user_address ON public.payments(user_address);
CREATE INDEX IF NOT EXISTS idx_payments_status ON public.payments(status);
CREATE INDEX IF NOT EXISTS idx_payments_network ON public.payments(network);
CREATE INDEX IF NOT EXISTS idx_payments_created_at ON public.payments(created_at DESC);

-- transactions: lightweight record of credited transactions for Usage page
CREATE TABLE IF NOT EXISTS public.transactions (
  hash text PRIMARY KEY,
  user_id uuid REFERENCES public.profiles(id),
  amount numeric NOT NULL,
  created_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_transactions_hash ON public.transactions(hash);
CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON public.transactions(user_id);

-- security_audit: generic audit log for login / payments security events
CREATE TABLE IF NOT EXISTS public.security_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type text NOT NULL,
  user_id uuid,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ===== Functions =====

-- Upsert profile by wallet, create wallet-local email if missing
CREATE OR REPLACE FUNCTION public.upsert_profile_for_wallet(p_wallet text)
RETURNS public.profiles
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_profile public.profiles;
  v_email text;
BEGIN
  IF p_wallet IS NULL OR length(p_wallet) = 0 THEN
    RAISE EXCEPTION 'wallet required';
  END IF;
  v_email := lower(p_wallet) || '@wallet.local';

  SELECT * INTO v_profile FROM public.profiles WHERE wallet_address = lower(p_wallet) LIMIT 1;
  IF NOT FOUND THEN
    INSERT INTO public.profiles (email, wallet_address, balance_usd_cents)
    VALUES (v_email, lower(p_wallet), 0)
    RETURNING * INTO v_profile;
  ELSE
    IF v_profile.email IS NULL THEN
      UPDATE public.profiles SET email = v_email, updated_at = now() WHERE id = v_profile.id RETURNING * INTO v_profile;
    END IF;
  END IF;
  RETURN v_profile;
END;
$$;

-- Security audit event
CREATE OR REPLACE FUNCTION public.audit_security_event(p_event_type text, p_user_id uuid, p_details jsonb)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  INSERT INTO public.security_audit (event_type, user_id, details) VALUES (p_event_type, p_user_id, COALESCE(p_details, '{}'::jsonb));
END;
$$;

-- Get full user profile by id (used by backend code)
CREATE OR REPLACE FUNCTION public.get_user_profile(p_user_id uuid)
RETURNS public.profiles
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_profile public.profiles;
BEGIN
  SELECT * INTO v_profile FROM public.profiles WHERE id = p_user_id;
  RETURN v_profile;
END;
$$;

-- Atomic balance add (numeric cents)
CREATE OR REPLACE FUNCTION public.add_balance_atomic(p_user_id uuid, p_amount_cents numeric)
RETURNS json
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  current_balance numeric;
  new_balance numeric;
BEGIN
  SELECT balance_usd_cents INTO current_balance FROM public.profiles WHERE id = p_user_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'User not found');
  END IF;
  new_balance := COALESCE(current_balance, 0) + p_amount_cents;
  UPDATE public.profiles SET balance_usd_cents = new_balance, updated_at = now() WHERE id = p_user_id;
  RETURN json_build_object('success', true, 'old_balance', current_balance, 'new_balance', new_balance, 'amount_added', p_amount_cents);
END;
$$;

-- Atomic balance deduct (numeric cents)
CREATE OR REPLACE FUNCTION public.deduct_balance_atomic(p_user_id uuid, p_amount_cents numeric)
RETURNS json
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  current_balance numeric;
  new_balance numeric;
BEGIN
  SELECT balance_usd_cents INTO current_balance FROM public.profiles WHERE id = p_user_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'User not found');
  END IF;
  IF COALESCE(current_balance, 0) < p_amount_cents THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient balance', 'current_balance', current_balance);
  END IF;
  new_balance := COALESCE(current_balance, 0) - p_amount_cents;
  UPDATE public.profiles SET balance_usd_cents = new_balance, updated_at = now() WHERE id = p_user_id;
  RETURN json_build_object('success', true, 'old_balance', current_balance, 'new_balance', new_balance, 'amount_deducted', p_amount_cents);
END;
$$;

-- Resolve user id from API key (prefix)
CREATE OR REPLACE FUNCTION public.resolve_api_key_user_id(p_key text)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_prefix varchar(12);
  v_user_id uuid;
BEGIN
  IF p_key IS NULL OR length(p_key) < 12 THEN
    RETURN NULL;
  END IF;
  v_prefix := substring(p_key from 1 for 12);
  SELECT user_id INTO v_user_id FROM public.api_keys WHERE key_prefix = v_prefix AND is_active = true AND (expires_at IS NULL OR expires_at > now()) LIMIT 1;
  RETURN v_user_id;
END;
$$;

-- ===== RLS (optional minimal policies for user-owned tables) =====
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY;

-- api_keys: users manage own rows
CREATE POLICY IF NOT EXISTS api_keys_select_own ON public.api_keys FOR SELECT USING (user_id = auth.uid());
CREATE POLICY IF NOT EXISTS api_keys_insert_own ON public.api_keys FOR INSERT WITH CHECK (user_id = auth.uid());
CREATE POLICY IF NOT EXISTS api_keys_delete_own ON public.api_keys FOR DELETE USING (user_id = auth.uid());

-- api_logs: users can view their own logs
CREATE POLICY IF NOT EXISTS api_logs_select_own ON public.api_logs FOR SELECT USING (user_id = auth.uid());
CREATE POLICY IF NOT EXISTS api_logs_insert_own ON public.api_logs FOR INSERT WITH CHECK (user_id = auth.uid());

-- transactions: users can view/insert own
CREATE POLICY IF NOT EXISTS transactions_select_own ON public.transactions FOR SELECT USING (user_id = auth.uid());
CREATE POLICY IF NOT EXISTS transactions_insert_own ON public.transactions FOR INSERT WITH CHECK (user_id = auth.uid());

-- End of minimal schema 