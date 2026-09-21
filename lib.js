import crypto from 'node:crypto';

export const GITHUB_API = 'https://api.github.com';
export const GITHUB_API_VERSION = '2026-03-10';

export const ORG = process.env.GITHUB_ORG || 'Skylark-MSP';
export const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'https://skylark-msp.github.io';
export const FRONTEND_URL = process.env.FRONTEND_URL || 'https://skylark-msp.github.io/msp-knowledge-hub/';
export const REDIRECT_URI = process.env.GITHUB_REDIRECT_URI || '';

const defaultRepos = [
  'l1-knowledge-base',
  'l2-knowledge-base',
  'shared-knowledge-base',
];

export const ALLOWED_REPOS = (process.env.KB_REPOS || defaultRepos.join(','))
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const REPO_META = {
  'l1-knowledge-base': {
    title: 'L1 Support',
    subtitle: 'Standard operating procedures, monitoring and first-level troubleshooting.',
    icon: 'L1',
  },
  'l2-knowledge-base': {
    title: 'L2 Support',
    subtitle: 'Advanced infrastructure troubleshooting, engineering procedures and RCA.',
    icon: 'L2',
  },
  'shared-knowledge-base': {
    title: 'Shared Knowledge',
    subtitle: 'Common SOPs, incident management, monitoring standards and escalation guides.',
    icon: 'KB',
  },
};

export const jsonHeaders = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
};

export function repoMeta(repo) {
  return REPO_META[repo] || { title: repo, subtitle: '', icon: 'KB' };
}

export function corsHeaders(request) {
  const origin = request.headers.get('origin');
  const headers = {
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, Range',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };

  if (origin === FRONTEND_ORIGIN) {
    headers['Access-Control-Allow-Origin'] = FRONTEND_ORIGIN;
  }

  return headers;
}

export function optionsResponse(request) {
  return new Response(null, { status: 204, headers: corsHeaders(request) });
}

export function withCors(request, headers = {}) {
  return { ...headers, ...corsHeaders(request) };
}

export function githubHeaders(token, accept = 'application/vnd.github+json') {
  const headers = {
    Accept: accept,
    'X-GitHub-Api-Version': GITHUB_API_VERSION,
    'User-Agent': 'Skylark-MSP-Knowledge-Hub',
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

export async function githubFetch(path, token, options = {}) {
  const url = path.startsWith('http') ? path : `${GITHUB_API}${path}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      ...githubHeaders(token, options.accept || 'application/vnd.github+json'),
      ...(options.headers || {}),
    },
  });
  return response;
}

export async function readJson(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

export function randomHex(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function hexKey(name, expectedBytes = 32) {
  const value = process.env[name];
  if (!value || !/^[0-9a-fA-F]+$/.test(value) || value.length !== expectedBytes * 2) {
    throw new Error(`${name} must be exactly ${expectedBytes * 2} hex characters.`);
  }
  return Buffer.from(value, 'hex');
}

export function createState() {
  const nonce = randomHex(24);
  const issued = Date.now().toString();
  const body = `${issued}.${nonce}`;
  const secret = hexKey('STATE_SECRET_HEX');
  const sig = crypto.createHmac('sha256', secret).update(body).digest('hex');
  return `${body}.${sig}`;
}

export function verifyState(state, maxAgeMs = 10 * 60 * 1000) {
  if (!state || typeof state !== 'string') return false;
  const parts = state.split('.');
  if (parts.length !== 3) return false;
  const [issued, nonce, sig] = parts;
  if (!/^\d+$/.test(issued) || !/^[0-9a-f]+$/i.test(nonce) || !/^[0-9a-f]+$/i.test(sig) || sig.length !== 64) return false;
  const age = Date.now() - Number(issued);
  if (age < 0 || age > maxAgeMs) return false;

  const body = `${issued}.${nonce}`;
  const secret = hexKey('STATE_SECRET_HEX');
  const expected = crypto.createHmac('sha256', secret).update(body).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(sig, 'hex'));
}

function encrypt(plaintext) {
  const key = hexKey('SESSION_SECRET_HEX');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, encrypted].map((x) => x.toString('base64url')).join('.');
}

function decrypt(token) {
  const [ivB64, tagB64, dataB64] = String(token || '').split('.');
  if (!ivB64 || !tagB64 || !dataB64) throw new Error('Invalid session token.');
  const key = hexKey('SESSION_SECRET_HEX');
  const iv = Buffer.from(ivB64, 'base64url');
  const tag = Buffer.from(tagB64, 'base64url');
  const data = Buffer.from(dataB64, 'base64url');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}

export function createSession(data) {
  const payload = {
    v: 1,
    iat: Date.now(),
    ...data,
  };
  return encrypt(JSON.stringify(payload));
}

export function readSession(request) {
  const header = request.headers.get('authorization') || '';
  if (!header.startsWith('Bearer ')) {
    throw new Error('Missing authorization.');
  }
  const token = header.slice(7).trim();
  const payload = JSON.parse(decrypt(token));
  if (!payload?.ghToken || !payload?.exp) throw new Error('Invalid session.');
  if (Date.now() >= Number(payload.exp)) throw new Error('Session expired.');
  return payload;
}


export async function isActiveOrgMember(token) {
  const response = await githubFetch(`/user/memberships/orgs/${encodeURIComponent(ORG)}`, token);
  if (!response.ok) return false;
  const membership = await readJson(response);
  return membership?.state === 'active';
}

export function encodePath(path) {
  return String(path || '')
    .split('/')
    .filter((part) => part.length > 0)
    .map((part) => encodeURIComponent(part))
    .join('/');
}

export function safeRepo(repo) {
  return typeof repo === 'string' && ALLOWED_REPOS.includes(repo);
}

export function safeFilePath(path) {
  if (!path || typeof path !== 'string') return false;
  const normalized = path.replaceAll('\\', '/');
  if (normalized.startsWith('/') || normalized.includes('../') || normalized === '..') return false;
  return /^[^\0]+$/.test(normalized);
}

export function isPreviewableFile(path) {
  return /\.(pdf|png|jpe?g|webp)$/i.test(path);
}

export function isDocumentFile(path) {
  return /\.(pdf|md|txt|docx|png|jpe?g|webp)$/i.test(path);
}
