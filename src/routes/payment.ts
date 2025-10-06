import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { ethers } from 'ethers';
import dotenv from 'dotenv';
dotenv.config();

import { paymentsDb } from '../services/paymentDatabase';
import { CAPX_PAYMASTER_ABI } from "../config/abi"
import { PaymentService } from '../services/payment';
import { supabase } from '../services/paymentDatabase';
import { CHAINS } from '../config/chains';

const router = Router();

const SIGNER_PRIVATE_KEY = process.env.CAPX_SIGNER_PRIVATE_KEY || '';
const paymentService = new PaymentService(SIGNER_PRIVATE_KEY);

const RPC_URLS: Record<number, string | undefined> = {
    11155111: process.env.SEPOLIA_RPC_URL,
};

function getProvider(chainId: number): ethers.JsonRpcProvider {
    const url = RPC_URLS[chainId];
    if (!url) throw new Error(`Missing RPC URL for chain ${chainId}`);
    return new ethers.JsonRpcProvider(url);
}

const quoteSchema = z.object({
    user_id: z.string(),
    user_address: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
    pay_asset: z.enum(['USDC', 'USDT']),
    pay_amount: z.number().positive(),
    network: z.string(),
});

/**
 * Create a quote for a payment
 */
router.post('/quote', async (req: Request, res: Response) => {
    try {
        const { user_id, user_address, pay_asset, pay_amount, network } = quoteSchema.parse(req.body);

        const quote = await paymentService.createQuote(user_address, pay_asset, pay_amount, network);

        // Create payment in database
        await paymentsDb.createPayment({
            receipt_id: quote.receiptId,
            user_id,
            user_address: user_address.toLowerCase(),
            network,
            chain_id: quote.chainId,
            token_symbol: quote.tokenSymbol,
            token_address: quote.asset,
            token_decimals: quote.tokenDecimals,
            amount_usd: quote.amountUSD,
            amount_wei: quote.amount,
            timestamp: quote.timestamp,
            signature: quote.signature,
            status: 'pending',
        });

        res.json({
            success: true,
            data: {
                receiptId: quote.receiptId,
                asset: quote.asset,
                amount: quote.amount,
                timestamp: quote.timestamp,
                signature: quote.signature,
                paymaster: quote.paymaster,
                expiresAt: quote.expiresAt,
                chainId: quote.chainId,
                network: network,
            },
        });
    } catch (error: any) {
        if (error instanceof z.ZodError) {
            return res.status(400).json({ success: false, error: 'Invalid request parameters', details: error.issues });
        }
        res.status(500).json({ success: false, error: error?.message || 'Failed to generate quote' });
    }
});

const statusSchema = z.object({ receipt_id: z.uuid() });

/**
 * Get the status of a payment
 */
router.get('/status/:receipt_id', async (req: Request, res: Response) => {
    try {
        const { receipt_id } = req.params;
        if (!statusSchema.safeParse({ receipt_id }).success) {
            return res.status(400).json({ success: false, error: 'Invalid receipt ID' });
        }
        const payment = await paymentsDb.getPaymentByReceiptId(receipt_id);
        if (!payment) return res.status(404).json({ success: false, error: 'Payment not found' });

        const isExpired = payment.status === 'pending' && Date.now() / 1000 > payment.timestamp + 1800;

        res.json({
            success: true,
            data: {
                receipt_id: payment.receipt_id,
                status: isExpired ? 'expired' : payment.status,
                tx_hash: payment.tx_hash,
                amount_usd: payment.amount_usd,
                token_symbol: payment.token_symbol,
                network: payment.network,
                expires_at: payment.timestamp + 1800,
                created_at: payment.created_at,
            },
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to fetch status' });
    }
});

/**
 * Get all payments for a user
 */
router.get('/payments/:user_address', async (req: Request, res: Response) => {
    try {
        const { user_address } = req.params;
        if (!/^0x[a-fA-F0-9]{40}$/.test(user_address)) {
            return res.status(400).json({ success: false, error: 'Invalid address format' });
        }
        const payments = await paymentsDb.getPaymentsByUserAddress(user_address);
        res.json({ success: true, data: payments });
    } catch (error: any) {
        res.status(500).json({ success: false, error: error?.message || 'Failed to fetch payments' });
    }
});

const verifyPaymentSchema = z.object({
    chainId: z.number(),
    txHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
    receiptId: z.string(),
    userId: z.string(),
    usdAmount: z.number().positive(),
});

/**
 * Verify a payment
 */
router.post('/verify-payment', async (req: Request, res: Response) => {
    try {
        const { chainId, txHash, receiptId, userId, usdAmount } = verifyPaymentSchema.parse(req.body);
        const provider = getProvider(chainId);

        const txReceipt = await provider.getTransactionReceipt(txHash);
        if (!txReceipt || txReceipt.status !== 1) return res.status(400).json({ error: 'Transaction not found or failed' });

        // Check the event logs for the payment for the receiptId
        const interfaceAbi = new ethers.Interface(CAPX_PAYMASTER_ABI as any);
        const matched = txReceipt.logs
            .map((l: any) => { try { return interfaceAbi.parseLog(l); } catch { return null; } })
            .filter(Boolean)
            .find((parsed: any) => parsed!.name === 'CapxPaymentReceived' && parsed!.args.receiptId === receiptId);

        if (!matched) return res.status(400).json({ error: 'Payment event not found in transaction logs' });

        const didComplete = await paymentsDb.completePaymentIfPending(receiptId, txHash);
        if (!didComplete) {
            return res.status(200).json({ success: true, note: 'already_processed' });
        }

        try {
            const amountCents = Math.round(usdAmount * 100);
            const { data: updateResult, error: updateError } = await supabase.rpc('add_balance_atomic', { p_user_id: userId, p_amount_cents: amountCents });
            if (updateError || !(updateResult as any)?.success) {
                return res.status(500).json({ error: 'Failed to update user balance' });
            }

            // Insert into transactions table for Usage page stats
            const { error: txError } = await supabase
                .from('transactions')
                .insert({
                    hash: txHash,
                    user_id: userId,
                    amount: usdAmount,  // Positive amount for top-up
                    created_at: new Date().toISOString()
                });

            if (txError) {
                console.error('Failed to insert transaction record:', txError);
                // Don't fail the response, just log the error
            }

            await supabase.rpc('audit_security_event', { p_event_type: 'payment_verified', p_user_id: userId, p_details: { chainId, txHash, receiptId, usdAmount } });
            return res.status(200).json({ success: true, newBalance: (updateResult as any).new_balance / 100 });
        } catch {
            return res.status(200).json({ success: true });
        }
    } catch (error: any) {
        if (error instanceof z.ZodError) {
            return res.status(400).json({ error: 'Invalid payload', details: error.issues });
        }
        res.status(500).json({ error: error?.message || 'Verification failed' });
    }
});

/**
 * List available assets for a network (symbol and decimals only)
 */
router.get('/assets', async (req: Request, res: Response) => {
    try {
        const network = (req.query.network as string) || 'sepolia';
        const chain = (CHAINS as any)[network];
        if (!chain || !chain.active) {
            return res.status(400).json({ success: false, error: 'Unsupported or inactive network' });
        }
        const tokens = chain.tokens || {};
        const data = Object.keys(tokens).map(symbol => ({
            symbol,
            decimals: tokens[symbol].decimals,
        }));
        res.json({ success: true, data });
    } catch (error: any) {
        res.status(500).json({ success: false, error: error?.message || 'Failed to fetch assets' });
    }
});

export default router;

