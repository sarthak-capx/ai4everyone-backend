import rateLimit from 'express-rate-limit';

export function createUserRateLimiter() {
    return rateLimit({
        windowMs: 60 * 1000,
        max: 100,
        keyGenerator: (req: any) => {
            const userId = req.user?.sub;
            if (userId) return `user:${userId}`;
            return `ip:${req.ip}`;
        },
        handler: (req: any, res: any) => {
            const key = req.rateLimit?.key;
            const isUserBased = key?.startsWith('user:');
            res.status(429).json({
                error: 'Rate limit exceeded',
                retryAfter: Math.ceil(req.rateLimit?.resetTime / 1000) || 60,
                message: isUserBased ? 'User rate limit exceeded' : 'IP rate limit exceeded'
            });
        },
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: false,
        skipFailedRequests: false
    });
}

export function createIpRateLimiter() {
    return rateLimit({
        windowMs: 60 * 1000,
        max: 80,
        keyGenerator: (req: any) => {
            const ip = req.ip;
            const userAgent = req.headers['user-agent'] || 'unknown';
            return `${ip}:${userAgent}`;
        },
        handler: (req: any, res: any) => {
            res.status(429).json({
                error: 'Too many requests, please try again later.',
                retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
            });
        },
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: false,
        skipFailedRequests: false
    });
}

export function createPaymentRateLimiter() {
    return rateLimit({
        windowMs: 60 * 1000,
        max: 5,
        keyGenerator: (req: any) => {
            return req.user?.sub || req.ip;
        },
        handler: (req: any, res: any) => {
            res.status(429).json({
                error: 'Too many payment attempts. Please wait before trying again.',
                retryAfter: 60
            });
        },
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: false,
        skipFailedRequests: false,
        skip: (req: any) => req.method !== 'POST'
    });
}

export function createProxyRateLimiter() {
    return rateLimit({
        windowMs: 60 * 1000,
        max: 50,
        keyGenerator: async (req: any) => {
            let userId: string | null = null;
            if (req.user?.sub) userId = req.user.sub;
            if (!userId) {
                const apiKey = req.headers['x-api-key'] || req.headers.authorization?.replace('Bearer ', '');
                if (apiKey) {
                    try {
                        const { getUserIdFromApiKey } = require('../routes/proxy');
                        userId = await getUserIdFromApiKey(apiKey);
                    } catch (error) {
                        console.warn('Failed to resolve user ID from API key:', error);
                    }
                }
            }
            if (userId) return `user:${userId}`;
            return `ip:${req.ip}`;
        },
        handler: (req: any, res: any) => {
            const key = req.rateLimit?.key;
            const isUserBased = key?.startsWith('user:');
            res.status(429).json({
                error: 'AI API rate limit exceeded',
                retryAfter: Math.ceil(req.rateLimit?.resetTime / 1000) || 60,
                message: isUserBased ? 'User rate limit exceeded' : 'IP rate limit exceeded'
            });
        },
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: false,
        skipFailedRequests: false
    });
} 