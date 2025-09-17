import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

export function csrfTokenRoute(req: Request, res: Response) {
    const csrfToken = crypto.randomBytes(32).toString('hex');
    (req.session as any).csrfToken = csrfToken;
    res.json({ csrfToken, timestamp: Date.now() });
}

export function csrfValidation(req: Request, res: Response, next: NextFunction) {
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
        return next();
    }
    if (req.headers['x-api-key']) {
        return next();
    }
    if (req.method === 'GET') {
        return next();
    }
    const csrfToken = req.headers['x-csrf-token'] || (req.body as any)?._csrf;
    const sessionToken = (req.session as any)?.csrfToken;
    if (!csrfToken || csrfToken !== sessionToken) {
        return res.status(403).json({
            error: 'CSRF token missing or invalid',
            message: 'Please refresh the page and try again'
        });
    }
    next();
} 