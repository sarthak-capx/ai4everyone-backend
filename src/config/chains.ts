export interface TokenConfig {
    address: string;
    decimals: number;
    symbol: string;
}

export interface ChainConfig {
    chainId: number;
    name: string;
    paymaster: string;
    active: boolean;
    tokens: {
        USDC?: TokenConfig;
        USDT?: TokenConfig;
    };
}

export const CHAINS: Record<string, ChainConfig> = {
    sepolia: {
        chainId: 11155111,
        name: 'Sepolia Testnet',
        paymaster: process.env.SEPOLIA_PAYMASTER_ADDRESS || '',
        active: true,
        tokens: {
            USDC: {
                address: process.env.USDC_ADDRESS_SEPOLIA || '',
                decimals: 6,
                symbol: 'USDC',
            },
            USDT: {
                address: process.env.USDT_ADDRESS_SEPOLIA || '',
                decimals: 6,
                symbol: 'USDT',
            },
        },
    },
};

export function getChain(networkOrChainId: string | number): ChainConfig | undefined {
    if (typeof networkOrChainId === 'string') {
        const chain = CHAINS[networkOrChainId];
        return chain?.active ? chain : undefined;
    }
    const chain = Object.values(CHAINS).find((c) => c.chainId === networkOrChainId);
    return chain?.active ? chain : undefined;
}

export function getActiveChains(): ChainConfig[] {
    return Object.values(CHAINS).filter((chain) => chain.active);
}

export function getToken(network: string, asset: 'USDC' | 'USDT'): TokenConfig | undefined {
    const chain = CHAINS[network];
    if (!chain || !chain.active) return undefined;
    return chain.tokens[asset];
} 