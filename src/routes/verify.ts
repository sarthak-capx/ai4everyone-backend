import express, { Request, Response } from 'express';
import { ethers } from 'ethers';
import { supabase, supabaseAnon, getUserSupabaseClient } from '../index';
import axios from 'axios';
import { Connection, PublicKey } from '@solana/web3.js';
import crypto from 'crypto';

const router = express.Router();

// Helper: Safe redirect function (strict host/path allowlist)
function safeRedirect(res: Response, redirect: string | undefined) {
    const DEFAULT = '/';
    const ALLOWED_HOSTS = new Set(['ai4everyone.vercel.app']);
    const ALLOWED_PATHS = new Set(['/', '/dashboard', '/profile', '/home']);

    if (!redirect) return res.redirect(DEFAULT);

    try {
        // Normalize relative paths to our trusted host
        const url = redirect.startsWith('/')
            ? new URL(`https://ai4everyone.vercel.app${redirect}`)
            : new URL(redirect);

        // Enforce HTTPS, no credentials, exact hostname
        if (url.protocol !== 'https:') return res.redirect(DEFAULT);
        if (url.username || url.password) return res.redirect(DEFAULT);
        if (!ALLOWED_HOSTS.has(url.hostname)) return res.redirect(DEFAULT);

        // Enforce path allowlist (exact or subpath of an allowed base)
        const pathAllowed =
            ALLOWED_PATHS.has(url.pathname) ||
            Array.from(ALLOWED_PATHS).some(p => p !== '/' && (url.pathname === p || url.pathname.startsWith(p + '/')));
        if (!pathAllowed) return res.redirect(DEFAULT);

        return res.redirect(url.toString());
    } catch {
        return res.redirect(DEFAULT);
    }
}

// This is our "phonebook" of blockchain networks.
const providers: { [key: number]: ethers.JsonRpcProvider } = {
    // Mainnets
    137: new ethers.JsonRpcProvider(process.env.POLYGON_RPC_URL),
    42161: new ethers.JsonRpcProvider(process.env.ARBITRUM_RPC_URL),
    10: new ethers.JsonRpcProvider(process.env.OPTIMISM_RPC_URL),
    8453: new ethers.JsonRpcProvider(process.env.BASE_RPC_URL),
    // Sepolia Testnet
    11155111: new ethers.JsonRpcProvider(process.env.ETH_SEPOLIA_RPC_URL),
};

// Map chain IDs to CoinGecko API IDs for price lookups
const chainIdToCoinGeckoId: { [key: number]: string } = {
    137: 'matic-network',
    42161: 'ethereum',
    10: 'ethereum',
    8453: 'ethereum',
    11155111: 'ethereum', // Use mainnet ETH price for testnet
};

router.get('/wallet-address', (req: Request, res: Response) => {
    const chain = req.query.chain;
    let paymentWalletAddress;
    if (chain === 'solana') {
        paymentWalletAddress = process.env.PAYMENT_WALLET_ADDRESS_SOL;
    } else {
        paymentWalletAddress = process.env.PAYMENT_WALLET_ADDRESS;
    }
    if (paymentWalletAddress) {
        res.status(200).json({ address: paymentWalletAddress });
    } else {
        res.status(500).json({ error: 'Payment wallet address is not configured on the server.' });
    }
});

router.post('/payment', async (req: Request, res: Response) => {
    const { txHash, chainId, userId, amount } = req.body;

    // Input validation (SAFE - doesn't break functionality)
    if (!txHash || !chainId || !userId || !amount) {
        return res.status(400).json({ error: 'Missing required transaction details.' });
    }

    // Validate transaction hash format (SAFE)
    if (typeof txHash !== 'string' || !txHash.startsWith('0x') || txHash.length !== 66) {
        return res.status(400).json({ error: 'Invalid transaction hash format.' });
    }

    // Validate chain ID (SAFE)
    if (!Number.isInteger(chainId) || chainId <= 0) {
        return res.status(400).json({ error: 'Invalid chain ID.' });
    }

    // Validate user ID format (SAFE)
    if (typeof userId !== 'string' || userId.length < 10) {
        return res.status(400).json({ error: 'Invalid user ID format.' });
    }

    // Validate amount (SAFE)
    const amountNum = parseFloat(amount);
    if (isNaN(amountNum) || amountNum <= 0 || amountNum > 10000) {
        return res.status(400).json({ error: 'Invalid amount. Must be between 0.01 and 10,000 USD.' });
    }

    const provider = providers[chainId];
    if (!provider) {
        return res.status(400).json({ error: 'Unsupported chain.' });
    }

    // Generate idempotency key for this payment attempt
    const idempotencyKey = crypto.createHash('sha256')
        .update(`${txHash}:${chainId}:${userId}:${amount}`)
        .digest('hex');

    try {
        // 1. ATOMIC: Try to insert payment record with idempotency key
        const { data: insertResult, error: insertError } = await supabaseAnon
            .rpc('insert_payment_attempt', {
                p_idempotency_key: idempotencyKey,
                p_tx_hash: txHash,
                p_chain_id: chainId,
                p_user_id: userId,
                p_amount: amountNum,
                p_status: 'pending'
            });

        if (insertError) {
            // Check if it's a duplicate key error
            if (insertError.message?.includes('duplicate key') || insertError.message?.includes('already exists')) {
                return res.status(409).json({ error: 'Payment attempt already in progress or completed.' });
            }
            console.error('Failed to insert payment attempt:', insertError);
            return res.status(500).json({ error: 'Failed to process payment.' });
        }

        if (!insertResult?.success) {
            return res.status(409).json({ error: insertResult?.error || 'Payment already processed.' });
        }

        // 2. Get the transaction details from the blockchain.
        const tx = await provider.getTransaction(txHash);
        if (!tx || !tx.to) {
            return res.status(404).json({ error: 'Transaction not found or has no recipient.' });
        }

        const receipt = await provider.getTransactionReceipt(txHash);
        if (!receipt || receipt.status !== 1) {
            return res.status(400).json({ error: 'Transaction failed or is not yet confirmed.' });
        }

        // 3. Verify the details.
        const recipientAddress = process.env.PAYMENT_WALLET_ADDRESS;
        const sentAmount = parseFloat(ethers.formatEther(tx.value)); // Amount from the transaction in crypto

        if (tx.to.toLowerCase() !== recipientAddress?.toLowerCase()) {
            return res.status(400).json({ error: 'Transaction sent to wrong wallet.' });
        }

        // Fetch current crypto price
        const coinId = chainIdToCoinGeckoId[chainId];
        if (!coinId) {
            return res.status(400).json({ error: 'Cannot determine price for this chain.' });
        }

        const priceResponse = await axios.get(`https://api.coingecko.com/api/v3/simple/price?ids=${coinId}&vs_currencies=usd`);
        const cryptoPriceUsd = priceResponse.data[coinId]?.usd;

        if (!cryptoPriceUsd) {
            return res.status(500).json({ error: 'Could not fetch crypto price.' });
        }

        const requiredCryptoAmount = parseFloat(amount) / cryptoPriceUsd;

        // Allow for a small tolerance (e.g., 0.1%) to account for minor price fluctuations
        if (sentAmount < requiredCryptoAmount * 0.999) {
            return res.status(400).json({ error: 'Paid amount is less than the required amount.' });
        }

        // 4. All checks passed. Update balance using SECURITY DEFINER function
        const amountCents = Math.round(parseFloat(amount) * 100);

        // Use SECURITY DEFINER function to update balance atomically
        const { data: updateResult, error: updateError } = await supabaseAnon
            .rpc('add_balance_atomic', {
                p_user_id: userId,
                p_amount_cents: amountCents
            });

        if (updateError || !updateResult?.success) {
            // Mark payment attempt as failed
            await supabaseAnon.rpc('complete_payment_attempt', {
                p_idempotency_key: idempotencyKey,
                p_status: 'failed',
                p_error_message: 'Failed to update balance'
            });

            console.error('Failed to update balance:', updateError || updateResult?.error);
            return res.status(500).json({ error: 'Failed to update user balance.' });
        }

        // 5. Record transaction using SECURITY DEFINER function
        const { error: recordError } = await supabaseAnon
            .rpc('insert_transaction', {
                p_hash: txHash,
                p_user_id: userId,
                p_amount: parseFloat(amount)
            });

        if (recordError) {
            console.error('Failed to record transaction:', recordError);
            // Don't fail the request if logging fails, but log it
        }

        // 6. Mark payment attempt as completed
        await supabaseAnon.rpc('complete_payment_attempt', {
            p_idempotency_key: idempotencyKey,
            p_status: 'completed',
            p_blockchain_data: {
                txHash,
                chainId,
                amount,
                amountCents,
                cryptoAmount: sentAmount,
                cryptoPrice: cryptoPriceUsd,
                recipientAddress: tx.to,
                blockNumber: receipt.blockNumber
            }
        });

        // 7. Audit the security event
        await supabaseAnon.rpc('audit_security_event', {
            p_event_type: 'payment_verified',
            p_user_id: userId,
            p_details: {
                txHash,
                chainId,
                amount,
                amountCents,
                cryptoAmount: sentAmount,
                cryptoPrice: cryptoPriceUsd,
                idempotencyKey
            }
        });

        res.status(200).json({
            success: true,
            message: 'Payment verified and balance updated.',
            newBalance: updateResult.new_balance / 100
        });

    } catch (error) {
        console.error('Verification error:', error);

        // Mark payment attempt as failed if we have an idempotency key
        if (idempotencyKey) {
            try {
                await supabaseAnon.rpc('complete_payment_attempt', {
                    p_idempotency_key: idempotencyKey,
                    p_status: 'failed',
                    p_error_message: error instanceof Error ? error.message : 'Unknown error'
                });
            } catch (completeError) {
                console.error('Failed to mark payment attempt as failed:', completeError);
            }
        }

        res.status(500).json({ error: 'Internal server error during transaction verification.' });
    }
});

// Solana payment verification endpoint
router.post('/solana-payment', async (req: Request, res: Response) => {
    const { txSignature, userId, amount } = req.body;

    // Input validation (SAFE - doesn't break functionality)
    if (!txSignature || !userId || !amount) {
        return res.status(400).json({ error: 'Missing required transaction details.' });
    }

    // Validate user ID format (SAFE)
    if (typeof userId !== 'string' || userId.length < 10) {
        return res.status(400).json({ error: 'Invalid user ID format.' });
    }

    // Validate amount (SAFE)
    const amountNum = parseFloat(amount);
    if (isNaN(amountNum) || amountNum <= 0 || amountNum > 10000) {
        return res.status(400).json({ error: 'Invalid amount. Must be between 0.01 and 10,000 USD.' });
    }

    const solanaRpcUrl = process.env.SOLANA_RPC_URL;
    const paymentWalletAddress = process.env.PAYMENT_WALLET_ADDRESS;
    if (!solanaRpcUrl || !paymentWalletAddress) {
        return res.status(500).json({ error: 'Solana RPC URL or payment wallet address not configured.' });
    }

    const connection = new Connection(solanaRpcUrl, 'confirmed');
    try {
        // 1. Check if transaction already processed using SECURITY DEFINER function
        const { data: transactionExists } = await supabaseAnon
            .rpc('check_transaction_exists', { p_hash: txSignature });

        if (transactionExists) {
            return res.status(409).json({ error: 'Transaction has already been processed.' });
        }

        // 2. Fetch transaction details
        const tx = await connection.getTransaction(txSignature, { commitment: 'confirmed' });
        if (!tx || !tx.meta || !tx.transaction) {
            return res.status(404).json({ error: 'Transaction not found.' });
        }

        // 3. Find transfer to payment wallet
        const paymentPubkey = new PublicKey(paymentWalletAddress);
        let found = false;
        let sentAmount = 0;
        const message = tx.transaction.message;
        for (const inst of message.instructions) {
            // Get the programId for this instruction
            const programId = message.accountKeys[inst.programIdIndex].toBase58();
            // Only check SOL transfers (system program)
            if (programId === '11111111111111111111111111111111') {
                // Get the account keys for this instruction
                const keys = inst.accounts.map(idx => message.accountKeys[idx].toBase58());
                const paymentIdx = keys.indexOf(paymentWalletAddress);
                if (paymentIdx !== -1) {
                    found = true;
                    // lamports transferred: difference in balances for payment wallet
                    const accountIdx = inst.accounts[paymentIdx];
                    sentAmount = tx.meta.postBalances[accountIdx] - tx.meta.preBalances[accountIdx];
                    break;
                }
            }
        }
        if (!found || sentAmount <= 0) {
            return res.status(400).json({ error: 'No SOL transfer to payment wallet found.' });
        }

        // 4. Check amount (convert lamports to SOL)
        const sentSol = sentAmount / 1e9;
        const priceResponse = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd');
        const solPriceUsd = priceResponse.data['solana']?.usd;
        if (!solPriceUsd) {
            return res.status(500).json({ error: 'Could not fetch SOL price.' });
        }
        const requiredSol = parseFloat(amount) / solPriceUsd;
        if (sentSol < requiredSol * 0.999) {
            return res.status(400).json({ error: 'Paid amount is less than the required amount.' });
        }

        // 5. Update user balance using SECURITY DEFINER function
        const amountCents = Math.round(parseFloat(amount) * 100);

        const { data: updateResult, error: updateError } = await supabaseAnon
            .rpc('add_balance_atomic', {
                p_user_id: userId,
                p_amount_cents: amountCents
            });

        if (updateError || !updateResult?.success) {
            console.error('Failed to update balance:', updateError || updateResult?.error);
            return res.status(500).json({ error: 'Failed to update user balance.' });
        }

        // 6. Record transaction using SECURITY DEFINER function
        const { error: insertError } = await supabaseAnon
            .rpc('insert_transaction', {
                p_hash: txSignature,
                p_user_id: userId,
                p_amount: parseFloat(amount)
            });

        if (insertError) {
            console.error('Failed to record Solana transaction:', insertError);
        }

        // 7. Audit the security event
        await supabaseAnon.rpc('audit_security_event', {
            p_event_type: 'solana_payment_verified',
            p_user_id: userId,
            p_details: {
                txSignature,
                amount,
                amountCents,
                solAmount: sentSol,
                solPrice: solPriceUsd
            }
        });

        res.status(200).json({ success: true, message: 'Solana payment verified and balance updated.' });
    } catch (error) {
        console.error('Solana verification error:', error);
        res.status(500).json({ error: 'Internal server error during Solana transaction verification.' });
    }
});

export default router; 