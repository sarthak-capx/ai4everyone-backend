export const CAPX_PAYMASTER_ABI = [
    {
        "inputs": [
            { "internalType": "string", "name": "_receiptId", "type": "string" },
            { "internalType": "address", "name": "_asset", "type": "address" },
            { "internalType": "uint256", "name": "_amount", "type": "uint256" },
            { "internalType": "uint256", "name": "_timestamp", "type": "uint256" },
            { "internalType": "bytes", "name": "_signature", "type": "bytes" }
        ],
        "name": "pay",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "anonymous": false,
        "inputs": [
            { "indexed": false, "internalType": "uint256", "name": "chainId", "type": "uint256" },
            { "indexed": false, "internalType": "string", "name": "receiptId", "type": "string" },
            { "indexed": false, "internalType": "address", "name": "payer", "type": "address" },
            { "indexed": false, "internalType": "address", "name": "asset", "type": "address" },
            { "indexed": false, "internalType": "uint256", "name": "amount", "type": "uint256" },
            { "indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256" }
        ],
        "name": "CapxPaymentReceived",
        "type": "event"
    }
] as const; 