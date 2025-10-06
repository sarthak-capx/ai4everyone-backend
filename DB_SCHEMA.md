# AI4Everyone Database Schema (Supabase)

This document describes the public schema of the Supabase Postgres database used by the backend. It is generated from the live database via Supabase and captures tables, columns, constraints, indexes, RLS policies, key functions, views, and installed extensions relevant to this app.

- Schema: `public` (unless noted)
- Conventions: amounts in cents as integers where noted; timestamps are `timestamptz` unless specified; UUIDs generated with `gen_random_uuid()`.

## Tables

### profiles
- id (uuid, PK, default gen_random_uuid())
- name (text, nullable)
- email (text, unique, nullable)
- wallet_address (text, nullable)
- api_key_hash (text)
- api_key_prefix (text)
- balance_usd_cents (numeric)
- created_at (timestamptz, default now())
- updated_at (timestamptz, default now())

Constraints/Indexes:
- PK: profiles_pkey (id)
- UNIQUE: unique_email (email)
- idx_profiles_email (email)
- idx_profiles_wallet (email WHERE email LIKE '%@wallet.local')
- idx_profiles_wallet_address (wallet_address)
- idx_profiles_id_balance (id, balance_usd_cents)

RLS:
- profiles_select_own (SELECT where id = auth.uid())
- profiles_update_own (UPDATE where id = auth.uid())
- profiles_service_role_access (ALL for service_role)

### api_keys
- id (uuid, PK, default gen_random_uuid())
- user_id (uuid, FK → profiles.id ON DELETE CASCADE)
- user_email (text)
- name (text)
- key_hash (text) — Argon2id
- key_prefix (varchar(12)) — first 12 chars
- key_checksum (varchar(8)) — SHA256 checksum
- key_salt (text)
- last_used_at (timestamptz)
- expires_at (timestamptz)
- is_active (boolean, default true)
- allowed_ips (text[])
- rate_limit_override (int)
- created_at (timestamptz, default now())

Indexes:
- idx_api_keys_user_id (user_id)

RLS:
- api_keys_select_own (SELECT where user_id = auth.uid())
- api_keys_insert_own (INSERT with_check user_id = auth.uid())
- api_keys_delete_own (DELETE where user_id = auth.uid())
- api_keys_authenticated_access (ALL where user_id = auth.uid())

### api_logs
- log_id (uuid, PK, default gen_random_uuid())
- user_id (uuid, FK → profiles.id)
- user_email (text)
- api_key_prefix_used (text)
- timestamp (timestamptz, default now())
- endpoint_called (text)
- inference_usage_json (jsonb)
- inference_cost_usd (numeric)
- markup_percentage (bigint)
- final_cost_usd_cents (numeric)
- status_code_returned (bigint)
- was_deducted (boolean)

Indexes:
- idx_api_logs_user_id (user_id)

RLS (via API key or auth uid):
- Users can view/insert/update own logs (policies for public/authenticated with appropriate qualifiers)
- API-key based select/insert allowed via prefix matching policy

### payments
- receipt_id (text, PK)
- user_id (text) — legacy linkage (nullable)
- user_address (text)
- network (text)
- chain_id (int)
- token_symbol (text)
- token_address (text)
- token_decimals (int)
- amount_usd (numeric(10,2))
- amount_wei (text)
- timestamp (bigint)
- signature (text)
- status (text, check in ('pending','completed'))
- tx_hash (text)
- created_at (timestamptz, default now())
- updated_at (timestamptz, default now())

Indexes:
- payments_pkey (receipt_id)
- idx_payments_user_id (user_id)
- idx_payments_user_address (user_address)
- idx_payments_status (status)
- idx_payments_network (network)
- idx_payments_created_at (created_at DESC)

### payment_attempts (idempotency)
- id (uuid, PK, default gen_random_uuid())
- idempotency_key (text, UNIQUE)
- tx_hash (text)
- chain_id (int)
- user_id (uuid, FK → profiles.id)
- amount_usd (numeric(10,2))
- status (text, check in ('pending','completed','failed','invalid'))
- blockchain_data (jsonb)
- error_message (text)
- created_at (timestamptz, default now())
- updated_at (timestamptz, default now())

Indexes:
- idx_payment_attempts_user_id, _status, _tx_hash, _idempotency_key, _created_at

RLS:
- Users can select own attempts; service_role can manage

### capx_payments / paymaster_intents / paymaster_payments
On-chain/paymaster processing tables:
- capx_payments: receipt-scoped paymaster events, status in ('pending','completed','failed','expired'); FK → profiles.id
- paymaster_intents: tracks signed intents; unique(receipt_id); FK → profiles.id
- paymaster_payments: finalized payment records; unique(receipt_id); FK → profiles.id

Common columns: receipt_id, user_id, chain_id, asset/token fields, amounts, timestamps, signature, status, tx_hash, created_at/updated_at.

### transactions
- hash (text, PK, UNIQUE)
- user_id (uuid, FK → profiles.id)
- amount (numeric)
- created_at (timestamptz, default now())

Indexes:
- idx_transactions_hash, idx_transactions_user_id

### rate_limits
- user_id (uuid, FK → profiles.id)
- window_start (timestamptz)
- request_count (bigint, default 0)

PK/Indexes:
- PK (user_id, window_start)
- idx_rate_limits_user_window

RLS:
- view/update own; permissive insert/update policies

### error_logs
- id (uuid, PK, default gen_random_uuid())
- function_name (text)
- error_state (text)
- error_message (text)
- error_detail (text)
- error_hint (text)
- user_id (uuid, FK → profiles.id)
- occurred_at (timestamptz, default now())

Indexes:
- idx_error_logs_user_id, _function_name, _occurred_at

### security_audit
- id (uuid, PK, default gen_random_uuid())
- event_type (text)
- user_id (uuid)
- details (jsonb, default '{}')
- created_at (timestamptz, default now())

## Views

### user_api_keys_safe
- Safe projection over api_keys (id, user_id, user_email, name, key_prefix, key_checksum, created_at, last_used_at, expires_at, is_active, allowed_ips, rate_limit_override)

## Functions (selected)
- add_balance_atomic(p_user_id uuid, p_amount_cents numeric) returns json [SECURITY DEFINER]
- deduct_balance_atomic(p_user_id uuid, p_amount_cents numeric) returns json [SECURITY DEFINER]
- update_balance_atomic(p_user_id uuid, p_amount_cents integer) returns void [SECURITY DEFINER]
- process_capx_payment(p_receipt_id text, p_user_id uuid, p_amount_usd numeric) returns json [SECURITY DEFINER]
- credit_balance_from_capx_payment(p_receipt_id text, p_user_address text, p_amount_usd numeric) returns json [SECURITY DEFINER]
- get_user_profile(p_user_id uuid) returns profiles [SECURITY DEFINER]
- resolve_api_key_user_id(p_key text) returns uuid [SECURITY DEFINER]
- validate_and_update_api_key(api_key_prefix text, api_key_checksum text) returns boolean [SECURITY DEFINER]
- insert_payment_attempt(...), complete_payment_attempt(...), get_payment_attempt_status(p_idempotency_key text)
- insert_transaction(p_hash text, p_user_id uuid, p_amount numeric)
- audit_security_event(p_event_type text, p_user_id uuid, p_details jsonb)
- upsert_profile_for_wallet(p_wallet text) returns profiles [SECURITY DEFINER]
- cleanup_old_capx_payments() returns integer

Note: Security definer functions are used to encapsulate logic under controlled privileges with RLS enabled for direct table access where applicable.

## RLS Policies (high level)
- profiles: users can select/update own; service_role ALL
- api_keys: users can select/insert/delete/ALL own
- api_logs: select/insert via user auth or API key prefix policy; users can select/update own
- payments/paymaster_*: users can select/manage own; service role update on some
- payment_attempts: service_role manage; users select own
- rate_limits: permissive insert/update; users select own
- transactions: service_role insert; users insert/select own
- security_audit/error_logs: service_role manage

## Extensions (not exhaustive)
- uuid-ossp, pgcrypto, pgjwt, pg_graphql, pg_stat_statements, vector, supabase_vault, pg_cron, pgaudit, timescaledb, http, pgroonga, plv8, etc.

## Notes for Developers
- Monetary values: prefer storing in cents (integer/numeric) for precision; convert to dollars at the edge.
- Use functions (e.g., add_balance_atomic, deduct_balance_atomic) for balance changes to avoid race conditions.
- API keys are not stored in plaintext. Use `key_prefix` + `key_checksum` for display/validation; verify hashes in application logic.
- RLS is enabled broadly. Use service_role only in backend-controlled functions and never expose it to clients.
- Payment processing uses `payment_attempts` for idempotency and `capx_payments`/`paymaster_*` tables for on-chain event tracking. 