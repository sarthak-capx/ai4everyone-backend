import cors from 'cors';

export function createCorsMiddleware() {
    const allowedOrigins = process.env.NODE_ENV === 'production'
        ? ['https://ai4everyone.vercel.app']
        : ['http://localhost:5173', 'http://localhost:3000', 'http://localhost:4173'];

    return cors({
        origin: function (origin, callback) {
            if (!origin) {
                return callback(new Error('Origin required - no bypasses allowed'));
            }
            if (allowedOrigins.includes(origin)) {
                return callback(null, true);
            } else {
                console.warn(`CORS blocked request from unauthorized origin: ${origin}`);
                return callback(new Error('Not allowed by CORS'));
            }
        },
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'x-signature'],
        exposedHeaders: ['X-Request-ID'],
        maxAge: 86400
    });
} 