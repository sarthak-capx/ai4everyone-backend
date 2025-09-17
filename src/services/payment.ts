import { ethers } from 'ethers';
import { v4 as uuidv4 } from 'uuid';
import { getChain, getToken } from '../config/chains';

// This will be passed to the frontend to be used in the payment flow
export interface PaymentQuote {
    receiptId: string;
    asset: string;
    amount: string;
    timestamp: number;
    signature: string;
    paymaster: string;
    chainId: number;
    network: string;
    tokenSymbol: string;
    tokenDecimals: number;
    amountUSD: number;
    expiresAt: number;
}

export class PaymentService {
    private signer: ethers.Wallet;

    constructor(privateKey: string) {
        if (!privateKey || !/^0x[a-fA-F0-9]{64}$/.test(privateKey)) {
            throw new Error('SIGNER_PRIVATE_KEY missing or invalid');
        }
        this.signer = new ethers.Wallet(privateKey);
    }

    async createQuote(
        userAddress: string,
        payAsset: 'USDC' | 'USDT',
        payAmountUSD: number,
        network: string
    ): Promise<PaymentQuote> {
        const chain = getChain(network);
        if (!chain) throw new Error(`Network ${network} not supported`);

        const token = getToken(network, payAsset);
        if (!token) throw new Error(`${payAsset} is not available on ${network}`);

        if (!chain.paymaster) throw new Error(`Paymaster not configured for ${network}`);

        const amountWei = ethers.parseUnits(payAmountUSD.toString(), token.decimals).toString();

        const receiptId = uuidv4();
        const timestamp = Math.floor(Date.now() / 1000);

        const digest = ethers.keccak256(
            ethers.AbiCoder.defaultAbiCoder().encode(
                ['string', 'address', 'uint256', 'address', 'uint256', 'uint256'],
                [receiptId, token.address, amountWei, userAddress, timestamp, chain.chainId]
            )
        );

        const signature = this.signer.signingKey.sign(digest).serialized;

        return {
            receiptId,
            asset: token.address,
            amount: amountWei,
            timestamp,
            signature,
            paymaster: chain.paymaster,
            chainId: chain.chainId,
            network: chain.name,
            tokenSymbol: token.symbol,
            tokenDecimals: token.decimals,
            amountUSD: payAmountUSD,
            expiresAt: timestamp + 1800
        };
    }

    getSignerAddress(): string {
        return this.signer.address;
    }
} 