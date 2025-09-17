import session from 'express-session';

class ProductionSessionStore extends session.Store {
    private sessions: Map<string, { data: any; expires: number }> = new Map();
    private cleanupInterval: NodeJS.Timeout;
    private readonly MAX_SESSIONS = 10000;
    private readonly CLEANUP_INTERVAL = 5 * 60 * 1000;
    private readonly MAX_SESSION_SIZE = 1024 * 1024;

    constructor() {
        super();
        this.cleanupInterval = setInterval(() => {
            this.cleanup();
        }, this.CLEANUP_INTERVAL);

        process.on('SIGTERM', () => this.cleanupOnShutdown());
        process.on('SIGINT', () => this.cleanupOnShutdown());
        process.on('exit', () => this.cleanupOnShutdown());
    }

    private cleanup() {
        try {
            const now = Date.now();
            let deletedCount = 0;
            for (const [sid, session] of this.sessions.entries()) {
                if (session.expires < now) {
                    this.sessions.delete(sid);
                    deletedCount++;
                }
            }
            if (this.sessions.size > this.MAX_SESSIONS) {
                const entries = Array.from(this.sessions.entries());
                entries.sort((a, b) => a[1].expires - b[1].expires);
                const toDelete = entries.slice(0, this.sessions.size - this.MAX_SESSIONS);
                toDelete.forEach(([sid]) => {
                    this.sessions.delete(sid);
                    deletedCount++;
                });
                console.warn(`Session store memory limit exceeded. Deleted ${toDelete.length} oldest sessions.`);
            }
            if (deletedCount > 0) {
                console.log(`Session cleanup: deleted ${deletedCount} sessions. Current sessions: ${this.sessions.size}`);
            }
        } catch (error) {
            console.error('Session cleanup failed:', error);
        }
    }

    get(sid: string, callback: (err: any, session?: any) => void) {
        try {
            const session = this.sessions.get(sid);
            if (!session) {
                return callback(null, null);
            }
            if (session.expires < Date.now()) {
                this.sessions.delete(sid);
                return callback(null, null);
            }
            callback(null, session.data);
        } catch (error) {
            console.error('Session get error:', error);
            callback(error, null);
        }
    }

    set(sid: string, sess: any, callback?: (err?: any) => void) {
        try {
            const sessionSize = JSON.stringify(sess).length;
            if (sessionSize > this.MAX_SESSION_SIZE) {
                const error = new Error('Session data too large');
                console.error('Session size limit exceeded:', sessionSize, 'bytes');
                return callback?.(error);
            }
            if (this.sessions.size >= this.MAX_SESSIONS) {
                this.cleanup();
                if (this.sessions.size >= this.MAX_SESSIONS) {
                    const error = new Error('Session store at capacity');
                    console.error('Session store at capacity, rejecting new session');
                    return callback?.(error);
                }
            }
            const expires = Date.now() + (sess.cookie?.maxAge || 24 * 60 * 60 * 1000);
            this.sessions.set(sid, { data: sess, expires });
            callback?.();
        } catch (error) {
            console.error('Session set error:', error);
            callback?.(error);
        }
    }

    destroy(sid: string, callback?: (err?: any) => void) {
        try {
            this.sessions.delete(sid);
            callback?.();
        } catch (error) {
            console.error('Session destroy error:', error);
            callback?.(error);
        }
    }

    touch(sid: string, sess: any, callback?: (err?: any) => void) {
        try {
            const existing = this.sessions.get(sid);
            if (existing) {
                existing.expires = Date.now() + (sess.cookie?.maxAge || 24 * 60 * 60 * 1000);
            }
            callback?.();
        } catch (error) {
            console.error('Session touch error:', error);
            callback?.(error);
        }
    }

    private cleanupOnShutdown() {
        try {
            if (this.cleanupInterval) {
                clearInterval(this.cleanupInterval);
                this.cleanupInterval = null as any;
            }
            this.sessions.clear();
            console.log('Session store destroyed successfully');
        } catch (error) {
            console.error('Session store destroy error:', error);
        }
    }
}

export function getSessionMiddleware() {
    if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
        throw new Error('SESSION_SECRET must be set and at least 32 characters long');
    }

    const sessionConfig: session.SessionOptions = {
        secret: process.env.SESSION_SECRET as string,
        name: 'ai4everyone.sid',
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000,
            path: '/'
        },
        resave: false,
        saveUninitialized: false,
        rolling: true,
        unset: 'destroy'
    };

    if (process.env.NODE_ENV === 'production') {
        sessionConfig.store = new ProductionSessionStore();
    } else {
        sessionConfig.store = new session.MemoryStore();
        console.warn('Using MemoryStore in development - this is fine for local development');
    }

    return session(sessionConfig);
} 