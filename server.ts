import 'dotenv/config';
import express, { type Request, type Response } from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const AUTH_STORE_PATH = path.resolve(__dirname, '.admin-auth.json');
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours
const SESSION_SECRET = process.env.ADMIN_SESSION_SECRET || crypto.randomBytes(32).toString('hex');

interface StoredAdminAuth {
  salt: string;
  hash: string;
  createdAt: string;
}

interface RateBucket {
  count: number;
  resetAt: number;
}

const attemptBuckets = new Map<string, RateBucket>();
const RATE_WINDOW_MS = 5 * 60 * 1000;
const RATE_LIMIT_MAX = 12;

function getClientIp(req: Request): string {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.trim()) {
    return fwd.split(',')[0].trim();
  }
  return req.ip || 'unknown';
}

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const bucket = attemptBuckets.get(ip);
  if (!bucket || now > bucket.resetAt) {
    attemptBuckets.set(ip, { count: 1, resetAt: now + RATE_WINDOW_MS });
    return true;
  }
  if (bucket.count >= RATE_LIMIT_MAX) {
    return false;
  }
  bucket.count += 1;
  return true;
}

function readStoredAuth(): StoredAdminAuth | null {
  try {
    if (!fs.existsSync(AUTH_STORE_PATH)) return null;
    const raw = fs.readFileSync(AUTH_STORE_PATH, 'utf8');
    const parsed = JSON.parse(raw) as Partial<StoredAdminAuth>;
    if (typeof parsed.salt === 'string' && typeof parsed.hash === 'string') {
      return {
        salt: parsed.salt,
        hash: parsed.hash,
        createdAt: typeof parsed.createdAt === 'string' ? parsed.createdAt : new Date().toISOString(),
      };
    }
    return null;
  } catch {
    return null;
  }
}

function getEnvAdminPassword(): string {
  return (process.env.ADMIN_PASSWORD || '').trim();
}

function constantTimeEqualsString(a: string, b: string): boolean {
  const digestA = crypto.createHash('sha256').update(a, 'utf8').digest();
  const digestB = crypto.createHash('sha256').update(b, 'utf8').digest();
  return crypto.timingSafeEqual(digestA, digestB);
}

function verifyPasswordAgainstStore(password: string): boolean {
  const envPwd = getEnvAdminPassword();
  if (envPwd.length > 0) {
    return constantTimeEqualsString(password, envPwd);
  }
  const stored = readStoredAuth();
  if (!stored) return false;
  const candidate = crypto.scryptSync(password, stored.salt, 64);
  const expected = Buffer.from(stored.hash, 'hex');
  if (candidate.length !== expected.length) return false;
  return crypto.timingSafeEqual(candidate, expected);
}

function issueAdminToken(adminLevel: 1 | 2, email: string): { token: string; expiresAt: number } {
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const payload = Buffer.from(
    JSON.stringify({ role: 'admin', adminLevel, email, exp: expiresAt }),
    'utf8'
  ).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return { token: `${payload}.${sig}`, expiresAt };
}

function verifyAdminToken(token: string): { valid: boolean; expiresAt?: number; adminLevel?: 1 | 2; email?: string } {
  if (!token || typeof token !== 'string') return { valid: false };
  const parts = token.split('.');
  if (parts.length !== 2) return { valid: false };
  const [payload, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  const sigBuf = Buffer.from(sig, 'utf8');
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return { valid: false };
  }
  try {
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
      role?: string;
      adminLevel?: number;
      email?: string;
      exp?: number;
    };
    if (decoded.role !== 'admin' || typeof decoded.exp !== 'number' || Date.now() > decoded.exp) {
      return { valid: false };
    }
    const level: 1 | 2 = decoded.adminLevel === 1 ? 1 : 2;
    return { valid: true, expiresAt: decoded.exp, adminLevel: level, email: decoded.email || '' };
  } catch {
    return { valid: false };
  }
}

const FIREBASE_PROJECT_ID = 'gen-lang-client-0139785554';
const BOOTSTRAPPED_ADMIN_EMAIL = 'trangpt50@fpt.edu.vn';
const FPT_TEACHER_REGEX = /^[^@]+@fpt\.edu\.vn$/i;
const GOOGLE_CERTS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
let cachedCerts: { certs: Record<string, string>; expiresAt: number } | null = null;

async function getGoogleFirebaseCerts(): Promise<Record<string, string>> {
  if (cachedCerts && Date.now() < cachedCerts.expiresAt) {
    return cachedCerts.certs;
  }
  const resp = await fetch(GOOGLE_CERTS_URL);
  if (!resp.ok) throw new Error('Failed to fetch Google Firebase certificates');
  const cacheControl = resp.headers.get('cache-control') || '';
  const maxAgeMatch = cacheControl.match(/max-age=(\d+)/);
  const ttlMs = maxAgeMatch ? Number(maxAgeMatch[1]) * 1000 : 3600 * 1000;
  const certs = (await resp.json()) as Record<string, string>;
  cachedCerts = { certs, expiresAt: Date.now() + ttlMs };
  return certs;
}

async function verifyFirebaseTeacherIdToken(
  idToken: string
): Promise<{ ok: boolean; email?: string; adminLevel?: 1 | 2 }> {
  try {
    const parts = idToken.split('.');
    if (parts.length !== 3) return { ok: false };
    const [headerB64, payloadB64, sigB64] = parts;
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8')) as { alg?: string; kid?: string };
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8')) as {
      aud?: string;
      iss?: string;
      exp?: number;
      iat?: number;
      sub?: string;
      email?: string;
      email_verified?: boolean;
    };
    if (header.alg !== 'RS256' || !header.kid) return { ok: false };
    const nowSec = Math.floor(Date.now() / 1000);
    if (
      payload.aud !== FIREBASE_PROJECT_ID ||
      payload.iss !== `https://securetoken.google.com/${FIREBASE_PROJECT_ID}` ||
      !payload.sub ||
      typeof payload.exp !== 'number' ||
      payload.exp <= nowSec
    ) {
      return { ok: false };
    }
    const certs = await getGoogleFirebaseCerts();
    const certPem = certs[header.kid];
    if (!certPem) return { ok: false };
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(`${headerB64}.${payloadB64}`);
    verifier.end();
    const validSig = verifier.verify(certPem, Buffer.from(sigB64, 'base64url'));
    if (!validSig) return { ok: false };
    const email = (payload.email || '').trim().toLowerCase();
    if (!payload.email_verified) {
      return { ok: false };
    }
    if (email === BOOTSTRAPPED_ADMIN_EMAIL) {
      return { ok: true, email, adminLevel: 1 };
    }
    if (FPT_TEACHER_REGEX.test(email)) {
      return { ok: true, email, adminLevel: 2 };
    }
    return { ok: false };
  } catch {
    return { ok: false };
  }
}

async function startServer() {
  const app = express();
  app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use(express.json({ limit: '64kb' }));

  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({ ok: true });
  });

  app.get('/api/admin/status', (_req: Request, res: Response) => {
    const envPwd = getEnvAdminPassword();
    if (envPwd.length > 0) {
      res.json({ configured: true, mode: 'env' });
      return;
    }
    const stored = readStoredAuth();
    if (stored) {
      res.json({ configured: true, mode: 'claimed' });
      return;
    }
    res.json({ configured: false, mode: 'claim_required' });
  });

  app.post('/api/admin/claim', async (req: Request, res: Response) => {
    if (getEnvAdminPassword().length > 0 || readStoredAuth() !== null) {
      res.status(409).json({ error: 'Mật khẩu quản trị đã được thiết lập trước đó.' });
      return;
    }
    const authHeader = req.headers.authorization || '';
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const teacherCheck = await verifyFirebaseTeacherIdToken(idToken);
    if (!teacherCheck.ok || teacherCheck.adminLevel !== 1 || !teacherCheck.email) {
      res.status(403).json({ error: 'Chỉ tài khoản Quản trị viên chính (Mức 1) đã xác thực mới có quyền thiết lập mật khẩu.' });
      return;
    }
    const password = typeof req.body?.password === 'string' ? req.body.password.trim() : '';
    if (password.length < 6 || password.length > 128) {
      res.status(400).json({ error: 'Mật khẩu quản trị phải từ 6 đến 128 ký tự.' });
      return;
    }
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    const record: StoredAdminAuth = {
      salt,
      hash,
      createdAt: new Date().toISOString(),
    };
    fs.writeFileSync(AUTH_STORE_PATH, JSON.stringify(record, null, 2), { mode: 0o600 });
    const session = issueAdminToken(1, teacherCheck.email);
    res.json({ ok: true, mode: 'claimed', token: session.token, expiresAt: session.expiresAt, adminLevel: 1 });
  });

  app.post('/api/admin/verify-password', async (req: Request, res: Response) => {
    const ip = getClientIp(req);
    if (!checkRateLimit(ip)) {
      res.status(429).json({ error: 'Bạn đã thử quá nhiều lần. Vui lòng đợi vài phút rồi thử lại.' });
      return;
    }
    const authHeader = req.headers.authorization || '';
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const teacherCheck = await verifyFirebaseTeacherIdToken(idToken);
    if (!teacherCheck.ok || !teacherCheck.adminLevel || !teacherCheck.email) {
      res.status(403).json({ error: 'Chỉ tài khoản Giáo viên @fpt.edu.vn đã xác thực Google mới có quyền mở khóa Quản trị.' });
      return;
    }
    const envPwd = getEnvAdminPassword();
    const stored = readStoredAuth();
    if (envPwd.length === 0 && !stored) {
      res.status(412).json({ error: 'Chưa thiết lập mật khẩu quản trị. Vui lòng liên hệ Quản trị viên chính.' });
      return;
    }
    const password = typeof req.body?.password === 'string' ? req.body.password.trim() : '';
    if (!password) {
      res.status(400).json({ error: 'Vui lòng nhập mật khẩu quản trị.' });
      return;
    }
    if (!verifyPasswordAgainstStore(password)) {
      res.status(401).json({ error: 'Mật khẩu quản trị chưa chính xác.' });
      return;
    }
    const session = issueAdminToken(teacherCheck.adminLevel, teacherCheck.email);
    res.json({
      ok: true,
      token: session.token,
      expiresAt: session.expiresAt,
      adminLevel: teacherCheck.adminLevel,
    });
  });

  app.get('/api/admin/session', (req: Request, res: Response) => {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const check = verifyAdminToken(token);
    if (!check.valid) {
      res.status(401).json({ authenticated: false });
      return;
    }
    res.json({ authenticated: true, expiresAt: check.expiresAt, adminLevel: check.adminLevel });
  });

  const isProduction =
    process.env.NODE_ENV === 'production' ||
    process.env.npm_lifecycle_event === 'start' ||
    Boolean(process.env.K_SERVICE);

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(
      express.static(distPath, {
        setHeaders: (res, filePath) => {
          if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
          }
        },
      })
    );
    app.get('*', (_req: Request, res: Response) => {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
