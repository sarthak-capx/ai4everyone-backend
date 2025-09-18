import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { ethers } from 'ethers';
import { CAPX_PAYMASTER_ABI } from '../config/abi';
import { CHAINS } from '../config/chains';
import { paymentsDb, supabase } from '../services/paymentDatabase';

const router = Router();

function timingSafeEqual(a: string, b: string): boolean {
    try {
        const ab = Buffer.from(a, 'hex');
        const bb = Buffer.from(b, 'hex');
        if (ab.length !== bb.length) return false;
        return crypto.timingSafeEqual(ab, bb);
    } catch {
        return false;
    }
}

function verifySignatureHmac(rawBody: string, signature: string | undefined, secret: string | undefined): boolean {
    if (!secret) return false;
    if (!signature) return false;
    try {
        const hmac = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
        return timingSafeEqual(hmac, String(signature));
    } catch {
        return false;
    }
}

router.post('/', async (req: Request, res: Response) => {
    try {
        const rawBody =
            typeof (req as any).rawBody === 'string'
                ? (req as any).rawBody
                : Buffer.isBuffer(req.body)
                    ? req.body.toString('utf8')
                    : JSON.stringify(req.body || {});

        const payload: any = (() => {
            try {
                if (Buffer.isBuffer(req.body)) return JSON.parse(rawBody);
                return req.body;
            } catch {
                return {};
            }
        })();

        // Require signature and secret
        const signature = req.headers['x-signature'] as string;
        const secret = process.env.MORALIS_WEBHOOK_SECRET;
        if (!secret) {
            return res.status(401).json({ success: false, error: 'Webhook secret not configured' });
        }
        if (!verifySignatureHmac(rawBody, signature, secret)) {
            return res.status(401).json({ success: false, processed: 0, error: 'invalid_signature' });
        }

        const chainId =
            typeof payload.chainId === 'number'
                ? payload.chainId
                : Number(payload.chainId || payload.block?.chainId || 0);

        const chainCfg = Object.values(CHAINS).find((c: any) => c.chainId === chainId);
        if (!chainCfg || !chainCfg.paymaster) {
            return res.status(200).json({ success: true, processed: 0, note: 'unsupported_chain_or_paymaster' });
        }
        const paymasterAddress = String(chainCfg.paymaster).toLowerCase();

        const iface = new ethers.Interface(CAPX_PAYMASTER_ABI as any);
        const logs: any[] = payload.logs || [];
        let processed = 0;

        for (const log of logs) {
            try {
                const address = String(log.address || '').toLowerCase();
                if (address !== paymasterAddress) continue;

                const topics = [log.topic0, log.topic1, log.topic2, log.topic3].filter(Boolean);
                const data = log.data || '0x';
                const parsed = iface.parseLog({ topics, data });
                if (!parsed || parsed.name !== 'CapxPaymentReceived') continue;

                const txHash: string = log.transactionHash;
                const evChainId = Number(parsed.args.chainId);
                const receiptId: string = parsed.args.receiptId;
                const payer: string = parsed.args.payer;
                const asset: string = parsed.args.asset;
                const amount: bigint = BigInt(parsed.args.amount.toString());
                const timestamp: number = Number(parsed.args.timestamp);

                const payment = await paymentsDb.getPaymentByReceiptId(receiptId);
                if (!payment) {
                    continue;
                }
                if (payment.status === 'completed') {
                    continue;
                }

                if (payment.chain_id !== evChainId) continue;
                if (payment.token_address && payment.token_address.toLowerCase() !== asset.toLowerCase()) continue;

                const didComplete = await paymentsDb.completePaymentIfPending(receiptId, txHash);
                if (!didComplete) {
                    continue;
                }

                const cents = Math.round((payment.amount_usd || 0) * 100);
                if (cents > 0) {
                    const { data: updateResult, error: updateError } = await supabase.rpc('add_balance_atomic', {
                        p_user_id: payment.user_id,
                        p_amount_cents: cents
                    });
                    if (!updateError && (updateResult as any)?.success) {
                        await supabase.rpc('audit_security_event', {
                            p_event_type: 'payment_verified_webhook',
                            p_user_id: payment.user_id,
                            p_details: {
                                chainId,
                                txHash,
                                receiptId,
                                payer,
                                asset,
                                amount: amount.toString(),
                                timestamp
                            }
                        });
                    }
                }

                processed++;
            } catch {
                // ignore and continue
            }
        }

        return res.status(200).json({ success: true, processed });
    } catch (error: any) {
        return res.status(200).json({ success: true, processed: 0, note: 'handler_error' });
    }
});

export default router; 