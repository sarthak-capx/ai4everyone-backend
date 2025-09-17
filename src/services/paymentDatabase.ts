import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = process.env.SUPABASE_URL as string;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY as string;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY as string | undefined;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
    throw new Error('Missing Supabase configuration for payments');
}

export interface Payment {
    receipt_id: string;
    user_id: string;
    user_address: string;
    network: string;
    chain_id: number;
    token_symbol: string;
    token_address: string;
    token_decimals: number;
    amount_usd: number;
    amount_wei: string;
    timestamp: number;
    signature: string;
    status: 'pending' | 'completed';
    tx_hash?: string;
    created_at?: string;
    updated_at?: string;
}

// Prefer service role on the server to avoid RLS issues on inserts
const supabaseKeyToUse = SUPABASE_SERVICE_ROLE_KEY || SUPABASE_ANON_KEY;
export const supabase = createClient(SUPABASE_URL, supabaseKeyToUse);

function logDbError(context: string, error: any) {
    const details = {
        code: (error && error.code) || undefined,
        message: (error && error.message) || undefined,
        details: (error && error.details) || undefined,
        hint: (error && error.hint) || undefined,
    };
    console.error(`[paymentDatabase][${context}]`, details);
}

export const paymentsDb = {
    async createPayment(payment: Omit<Payment, 'created_at' | 'updated_at'>): Promise<Payment> {
        const { error } = await supabase
            .from('payments')
            .insert(payment);
        if (error) {
            logDbError('createPayment error', error);
            throw new Error(error.message || 'createPayment failed');
        }
        return payment as Payment;
    },

    async getPaymentByReceiptId(receiptId: string): Promise<Payment | null> {
        const { data, error } = await supabase
            .from('payments')
            .select('*')
            .eq('receipt_id', receiptId)
            .single();
        if (error && (error as any).code !== 'PGRST116') {
            logDbError('getPaymentByReceiptId error', error);
            throw new Error(error.message || 'getPaymentByReceiptId failed');
        }
        return (data as Payment) || null;
    },

    async updatePaymentStatus(receiptId: string, status: 'completed', txHash: string): Promise<Payment> {
        const { error } = await supabase
            .from('payments')
            .update({ status, tx_hash: txHash, updated_at: new Date().toISOString() })
            .eq('receipt_id', receiptId);
        if (error) {
            logDbError('updatePaymentStatus error', error);
            throw new Error(error.message || 'updatePaymentStatus failed');
        }
        return { receipt_id: receiptId, status, tx_hash: txHash } as Payment;
    },

    async completePaymentIfPending(receiptId: string, txHash: string): Promise<boolean> {
        const { data, error } = await supabase
            .from('payments')
            .update({ status: 'completed', tx_hash: txHash, updated_at: new Date().toISOString() })
            .eq('receipt_id', receiptId)
            .eq('status', 'pending')
            .select('receipt_id');

        if (error) {
            logDbError('completePaymentIfPending error', error);
            throw new Error(error.message || 'completePaymentIfPending failed');
        }
        return Array.isArray(data) && data.length > 0;
    },

    async getPaymentsByUserAddress(userAddress: string): Promise<Payment[]> {
        const { data, error } = await supabase
            .from('payments')
            .select('*')
            .eq('user_address', userAddress.toLowerCase())
            .order('created_at', { ascending: false });
        if (error) {
            logDbError('getPaymentsByUserAddress error', error);
            throw new Error(error.message || 'getPaymentsByUserAddress failed');
        }
        return (data as Payment[]) || [];
    }
};