const GITHUB_API = 'https://api.github.com';
const GITHUB_API_VERSION = '2026-03-10';

const DEFAULT_REPOS = [
  'l1-knowledge-base',
  'l2-knowledge-base',
  'shared-knowledge-base',
];

const DOCUMENT_HISTORY_FILE = '_DOCUMENT-HISTORY.csv';
const AUDIT_TABLE = 'audit_logs';
const AUDIT_EVENTS = ['LOGIN', 'LOGOUT', 'KB_VIEW', 'DOCUMENT_VIEW'];
const LEAD_TEAM_SLUG = 'msp-leads';

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
    title: 'MSP Common Knowledge Base',
    subtitle: 'Common SOPs, incident management, monitoring standards and escalation guides.',
    icon: 'KB',
  },
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extraHeaders,
    },
  });
}

function config(env) {
  return {
    org: env.GITHUB_ORG || 'Skylark-MSP',
    frontendUrl: (env.FRONTEND_URL || 'https://skylark-msp.github.io/msp-knowledge-hub/').replace(/\/$/, ''),
    frontendOrigin: env.FRONTEND_ORIGIN || 'https://skylark-msp.github.io',
    repos: (env.KB_REPOS || DEFAULT_REPOS.join(','))
      .split(',')
      .map((x) => x.trim())
      .filter(Boolean),
  };
}

function corsHeaders(request, env) {
  const origin = request.headers.get('Origin');
  const headers = {
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
  if (origin === config(env).frontendOrigin) {
    headers['Access-Control-Allow-Origin'] = origin;
  }
  return headers;
}

function withCors(response, request, env, extra = {}) {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(corsHeaders(request, env))) headers.set(k, v);
  for (const [k, v] of Object.entries(extra)) headers.set(k, v);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function options(request, env) {
  return new Response(null, { status: 204, headers: corsHeaders(request, env) });
}

function randomBytes(size) {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytes;
}

function b64url(bytes) {
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64urlToBytes(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4);
  const str = atob(base64);
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i);
  return out;
}

function utf8(value) {
  return new TextEncoder().encode(value);
}

function text(bytes) {
  return new TextDecoder().decode(bytes);
}

function normalizeSecret(secret, name) {
  const value = String(secret ?? '').trim();
  if (!value) throw new Error(`${name} is not configured.`);
  return value;
}

async function deriveSecretKey(secret, name) {
  const value = normalizeSecret(secret, name);
  const digest = await crypto.subtle.digest('SHA-256', utf8(value));
  return new Uint8Array(digest);
}

async function importHmac(secret, name = 'STATE_SECRET_HEX') {
  const bytes = await deriveSecretKey(secret, name);
  return crypto.subtle.importKey(
    'raw',
    bytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

async function importAes(secret, name = 'SESSION_SECRET_HEX') {
  const bytes = await deriveSecretKey(secret, name);
  return crypto.subtle.importKey(
    'raw',
    bytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

async function sign(value, secret, name = 'STATE_SECRET_HEX') {
  const key = await importHmac(secret, name);
  return b64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8(value))));
}

async function secureRandomToken() {
  return b64url(randomBytes(32));
}

function parseCookies(request) {
  const raw = request.headers.get('Cookie') || '';
  const result = {};
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    result[key] = value;
  }
  return result;
}

function cookie(name, value, attrs = {}) {
  const parts = [`${name}=${value}`];
  if (attrs.maxAge !== undefined) parts.push(`Max-Age=${attrs.maxAge}`);
  if (attrs.path) parts.push(`Path=${attrs.path}`);
  if (attrs.httpOnly) parts.push('HttpOnly');
  if (attrs.secure) parts.push('Secure');
  if (attrs.sameSite) parts.push(`SameSite=${attrs.sameSite}`);
  return parts.join('; ');
}

async function encryptJson(payload, secret) {
  const key = await importAes(secret, 'SESSION_SECRET_HEX');
  const iv = randomBytes(12);
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      utf8(JSON.stringify(payload))
    )
  );
  return `${b64url(iv)}.${b64url(encrypted)}`;
}

async function decryptJson(token, secret) {
  const [ivPart, cipherPart] = String(token || '').split('.');
  if (!ivPart || !cipherPart) throw new Error('Invalid session.');
  const key = await importAes(secret, 'SESSION_SECRET_HEX');
  const iv = b64urlToBytes(ivPart);
  const ciphertext = b64urlToBytes(cipherPart);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(text(new Uint8Array(plain)));
}

async function createState(env) {
  const nonce = await secureRandomToken();
  const issued = Date.now().toString();
  const body = `${issued}.${nonce}`;
  const signature = await sign(body, env.STATE_SECRET_HEX);
  return `${body}.${signature}`;
}

async function verifyState(state, env, maxAgeMs = 10 * 60 * 1000) {
  try {
    const [issued, nonce, signature] = String(state || '').split('.');
    if (!issued || !nonce || !signature || !/^\d+$/.test(issued)) return false;
    const age = Date.now() - Number(issued);
    if (age < 0 || age > maxAgeMs) return false;
    const body = `${issued}.${nonce}`;
    const key = await importHmac(env.STATE_SECRET_HEX, 'STATE_SECRET_HEX');
    return crypto.subtle.verify('HMAC', key, b64urlToBytes(signature), utf8(body));
  } catch {
    return false;
  }
}

async function githubFetch(path, token, init = {}) {
  const url = path.startsWith('http') ? path : `${GITHUB_API}${path}`;
  const headers = new Headers(init.headers || {});
  headers.set('Accept', headers.get('Accept') || 'application/vnd.github+json');
  headers.set('X-GitHub-Api-Version', GITHUB_API_VERSION);
  headers.set('User-Agent', 'Skylark-MSP-Knowledge-Hub');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  return fetch(url, { ...init, headers });
}

async function readJson(response) {
  try { return await response.json(); } catch { return null; }
}

async function readText(response) {
  try { return await response.text(); } catch { return ''; }
}

function parseCsvLine(line) {
  const fields = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') {
        current += '"';
        i++;
      } else if (ch === '"') {
        quoted = false;
      } else {
        current += ch;
      }
    } else if (ch === ',') {
      fields.push(current.trim());
      current = '';
    } else if (ch === '"' && current.trim() === '') {
      quoted = true;
    } else {
      current += ch;
    }
  }
  fields.push(current.trim());
  return fields;
}

function parseCsv(textValue) {
  const rows = String(textValue || '')
    .replace(/^\uFEFF/, '')
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter((line) => line.trim() !== '');
  if (!rows.length) return [];

  const headers = parseCsvLine(rows[0]).map((x) => x.toLowerCase());
  return rows.slice(1).map((line) => {
    const values = parseCsvLine(line);
    const item = {};
    headers.forEach((header, index) => {
      item[header] = values[index] || '';
    });
    return item;
  });
}

async function loadDocumentHistory(token, org, repo, branch) {
  const response = await githubFetch(
    `/repos/${encodeURIComponent(org)}/${encodeURIComponent(repo)}/contents/${DOCUMENT_HISTORY_FILE}?ref=${encodeURIComponent(branch)}`,
    token,
    { headers: { Accept: 'application/vnd.github.raw+json' } },
  );

  if (response.status === 404) return new Map();
  if (response.status === 401) throw new Error('GitHub authorization is no longer valid. Please sign in again.');
  if (!response.ok) {
    console.error('Document history file could not be loaded', {
      repo,
      status: response.status,
    });
    return new Map();
  }

  const rows = parseCsv(await readText(response));
  const map = new Map();

  // Expected format:
  // File Name,File Path,Creator
  // Created Date is intentionally not used by the portal.
  for (const row of rows) {
    const filePath = String(row['file path'] || '')
      .trim()
      .replaceAll('\\', '/')
      .replace(/^\/+/, '');
    const fileName = String(row['file name'] || '').trim();
    const creator = String(row.creator || '').trim();

    if (!filePath && !fileName) continue;

    const metadata = {
      fileName,
      filePath,
      creator,
    };

    if (filePath) map.set(`path:${filePath}`, metadata);
    if (fileName) map.set(`name:${fileName.toLowerCase()}`, metadata);
  }

  return map;
}

function documentMetadata(history, file) {
  if (!history) return { creator: '' };

  const exact = history.get(`path:${file.path}`);
  if (exact) return { creator: exact.creator || '' };

  const byName = history.get(`name:${file.name.toLowerCase()}`);
  if (byName) return { creator: byName.creator || '' };

  return { creator: '' };
}

function redirect(url) {
  return new Response(null, { status: 302, headers: { Location: url } });
}

function redirectError(env, message) {
  const url = new URL(env.FRONTEND_URL || 'https://skylark-msp.github.io/msp-knowledge-hub/');
  url.searchParams.set('error', message);
  return redirect(url.toString());
}

function clearCookie() {
  return cookie('skylark_session', '', { maxAge: 0, path: '/', httpOnly: true, secure: true, sameSite: 'None' });
}

async function sessionCookie(session, maxAge) {
  return cookie('skylark_session', session, {
    maxAge: Math.max(60, Math.floor(maxAge / 1000)),
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'None',
  });
}

function bearerToken(request) {
  const header = request.headers.get('Authorization') || '';
  if (!header.toLowerCase().startsWith('bearer ')) return null;
  const token = header.slice(7).trim();
  return token || null;
}

async function loadSession(request, env) {
  const cookies = parseCookies(request);
  const token = bearerToken(request) || cookies.skylark_session;
  if (!token) return { session: null, setCookie: null };

  const session = await decryptJson(token, env.SESSION_SECRET_HEX);
  if (!session?.ghToken || !session?.exp) throw new Error('Invalid session.');
  if (Date.now() >= Number(session.exp)) throw new Error('Session expired.');
  return { session, setCookie: null };
}

async function hasRepoAccess(token, org, repo) {
  const response = await githubFetch(`/repos/${encodeURIComponent(org)}/${encodeURIComponent(repo)}`, token);
  if (response.status === 401) {
    throw new Error('GitHub authorization is no longer valid. Please sign in again.');
  }
  if (!response.ok) return null;
  const data = await readJson(response);
  if (!data) return null;
  if (data.permissions && data.permissions.pull === false) return null;
  return data;
}

function repoMeta(repo) {
  return REPO_META[repo] || { title: repo, subtitle: '', icon: 'KB' };
}

function safeRepo(repo, cfg) {
  return typeof repo === 'string' && cfg.repos.includes(repo);
}

function safePath(path) {
  if (!path || typeof path !== 'string') return false;
  const normalized = path.replaceAll('\\', '/');
  if (normalized.startsWith('/') || normalized.includes('../') || normalized === '..') return false;
  return !normalized.includes('\0');
}

function isDocumentFile(path) {
  if (!path || typeof path !== 'string') return false;

  const normalized = path.replaceAll('\\', '/');
  const fileName = normalized.split('/').pop().toLowerCase();

  // Internal metadata/control files must never appear in the user portal.
  if (fileName === DOCUMENT_HISTORY_FILE.toLowerCase()) return false;
  if (fileName.startsWith('_')) return false;

  return /\.(pdf|md|txt|docx|png|jpe?g|webp)$/i.test(normalized);
}

function missingAuthConfig(env) {
  const required = [
    'GITHUB_APP_CLIENT_ID',
    'GITHUB_APP_CLIENT_SECRET',
    'STATE_SECRET_HEX',
    'SESSION_SECRET_HEX',
  ];
  return required.filter((name) => !String(env[name] ?? '').trim());
}

function logAuthConfigDiagnostics(env, context) {
  const missing = missingAuthConfig(env);
  console.log('Auth runtime configuration check', {
    context,
    missing,
    clientIdPresent: Boolean(String(env.GITHUB_APP_CLIENT_ID ?? '').trim()),
    clientSecretPresent: Boolean(String(env.GITHUB_APP_CLIENT_SECRET ?? '').trim()),
    stateSecretLength: String(env.STATE_SECRET_HEX ?? '').trim().length,
    sessionSecretLength: String(env.SESSION_SECRET_HEX ?? '').trim().length,
  });
  return missing;
}

async function auditLog(env, event) {
  if (!env.DB) {
    console.warn('Audit database binding DB is not configured; audit event was not stored.', {
      eventType: event?.eventType || null,
      repo: event?.repo || null,
      path: event?.path || null,
    });
    return false;
  }

  try {
    const eventType = String(event?.eventType || '').trim().toUpperCase();
    if (!AUDIT_EVENTS.includes(eventType)) return false;

    await env.DB.prepare(`
      INSERT INTO ${AUDIT_TABLE}
        (event_type, github_id, username, display_name, repo, path, document_name)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      eventType,
      event?.githubId ?? null,
      String(event?.username || '').trim() || 'unknown',
      String(event?.displayName || '').trim() || String(event?.username || '').trim() || 'unknown',
      event?.repo ? String(event.repo) : null,
      event?.path ? String(event.path) : null,
      event?.documentName ? String(event.documentName) : null,
    ).run();

    return true;
  } catch (error) {
    // Audit failure must not make document access or login fail.
    console.error('Audit log write failed', {
      name: error?.name || 'Error',
      message: error?.message || String(error),
      eventType: event?.eventType || null,
      repo: event?.repo || null,
      path: event?.path || null,
    });
    return false;
  }
}

async function isMspLead(token, org, username) {
  const login = String(username || '').trim();
  if (!login) return false;

  const response = await githubFetch(
    `/orgs/${encodeURIComponent(org)}/teams/${encodeURIComponent(LEAD_TEAM_SLUG)}/memberships/${encodeURIComponent(login)}`,
    token,
  );

  if (response.status === 401) {
    throw new Error('GitHub authorization is no longer valid. Please sign in again.');
  }
  if (response.status === 404) return false;
  if (!response.ok) {
    console.error('MSP-Leads membership check failed', {
      status: response.status,
      username: login,
    });
    return false;
  }

  const membership = await readJson(response);
  return membership?.state === 'active';
}

async function requireLeadSession(request, env) {
  const result = await loadSession(request, env);
  if (!result.session) return { result, lead: false, response: null };
  const cfg = config(env);
  const lead = await isMspLead(result.session.ghToken, cfg.org, result.session.user?.login);
  return { result, lead, response: null };
}

async function apiAdminAudit(request, env, url) {
  try {
    const { result, lead } = await requireLeadSession(request, env);
    if (!result.session) {
      return withCors(json({ error: 'Not authenticated.' }, 401), request, env);
    }
    if (!lead) {
      return withCors(json({ error: 'MSP-Leads access is required.' }, 403), request, env);
    }
    if (!env.DB) {
      return withCors(json({ error: 'Audit database is not configured. Bind the D1 database as DB and try again.' }, 503), request, env);
    }

    const requestedLimit = Number(url.searchParams.get('limit') || 100);
    const requestedOffset = Number(url.searchParams.get('offset') || 0);
    const limit = Number.isFinite(requestedLimit) ? Math.min(Math.max(Math.trunc(requestedLimit), 1), 200) : 100;
    const offset = Number.isFinite(requestedOffset) ? Math.min(Math.max(Math.trunc(requestedOffset), 0), 100000) : 0;

    const eventType = String(url.searchParams.get('event') || '').trim().toUpperCase();
    const repo = String(url.searchParams.get('repo') || '').trim();
    const username = String(url.searchParams.get('user') || '').trim();

    const where = [];
    const params = [];
    if (eventType && AUDIT_EVENTS.includes(eventType)) {
      where.push('event_type = ?');
      params.push(eventType);
    }
    if (repo) {
      where.push('repo = ?');
      params.push(repo);
    }
    if (username) {
      where.push('username LIKE ?');
      params.push(`%${username}%`);
    }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const countRow = await env.DB.prepare(
      `SELECT COUNT(*) AS total FROM ${AUDIT_TABLE} ${whereSql}`
    ).bind(...params).first();
    const total = Number(countRow?.total || 0);

    const rowsResult = await env.DB.prepare(`
      SELECT
        id,
        created_at,
        event_type,
        github_id,
        username,
        display_name,
        repo,
        path,
        document_name
      FROM ${AUDIT_TABLE}
      ${whereSql}
      ORDER BY id DESC
      LIMIT ? OFFSET ?
    `).bind(...params, limit, offset).all();

    const rows = rowsResult?.results || [];
    return withCors(
      json({
        rows,
        total,
        limit,
        offset,
        hasMore: offset + rows.length < total,
      }),
      request,
      env,
      result.setCookie ? { 'Set-Cookie': result.setCookie } : {},
    );
  } catch (error) {
    if (String(error?.message || '').includes('GitHub authorization is no longer valid')) {
      return withCors(json({ error: error.message }, 401), request, env, { 'Set-Cookie': clearCookie() });
    }
    console.error('Admin audit request failed', {
      name: error?.name || 'Error',
      message: error?.message || String(error),
    });
    return withCors(json({ error: error.message || 'Could not load audit history.' }, 500), request, env);
  }
}

async function login(request, env) {
  const missing = logAuthConfigDiagnostics(env, 'login');
  if (missing.length) {
    console.error('Missing required authentication configuration', { missing });
    return new Response('GitHub App backend is not configured yet.', { status: 500 });
  }
  const state = await createState(env);
  const callback = new URL('/auth/callback', request.url).toString();
  const url = new URL('https://github.com/login/oauth/authorize');
  url.searchParams.set('client_id', env.GITHUB_APP_CLIENT_ID);
  url.searchParams.set('redirect_uri', callback);
  url.searchParams.set('state', state);
  // No additional scope is requested. GitHub App permissions are defined by the App installation.
  return new Response(null, {
    status: 302,
    headers: {
      Location: url.toString(),
      'Set-Cookie': cookie('skylark_oauth_state', state, {
        maxAge: 600,
        path: '/auth/callback',
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
      }),
      'Cache-Control': 'no-store',
    },
  });
}

async function callback(request, env) {
  try {
    const missing = logAuthConfigDiagnostics(env, 'callback');
    if (missing.length) {
      console.error('Missing required authentication configuration', { missing });
      return redirectError(env, 'GitHub App backend is not configured yet.');
    }

    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const githubError = url.searchParams.get('error');
    if (githubError) return redirectError(env, `GitHub authorization was cancelled (${githubError}).`);

    const cookies = parseCookies(request);
    if (!state || !cookies.skylark_oauth_state || state !== cookies.skylark_oauth_state) {
      return redirectError(env, 'Authentication request was invalid or expired. Please sign in again.');
    }
    if (!(await verifyState(state, env))) {
      return redirectError(env, 'Authentication request was invalid or expired. Please sign in again.');
    }
    if (!code) return redirectError(env, 'GitHub did not return an authorization code.');

    const callbackUrl = new URL('/auth/callback', request.url).toString();
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'User-Agent': 'Skylark-MSP-Knowledge-Hub' },
      body: JSON.stringify({
        client_id: env.GITHUB_APP_CLIENT_ID,
        client_secret: env.GITHUB_APP_CLIENT_SECRET,
        code,
        redirect_uri: callbackUrl,
      }),
    });
    const token = await readJson(tokenResponse);
    if (!tokenResponse.ok || !token?.access_token) {
      console.error('GitHub token exchange failed', {
        status: tokenResponse.status,
        hasAccessToken: Boolean(token?.access_token),
        error: token?.error || null,
      });
      return redirectError(env, 'GitHub token exchange failed. Please try again.');
    }

    const meResponse = await githubFetch('/user', token.access_token);
    const me = await readJson(meResponse);
    if (!meResponse.ok || !me?.login) return redirectError(env, 'Could not verify the GitHub account.');

    const membershipResponse = await githubFetch(`/user/memberships/orgs/${encodeURIComponent(config(env).org)}`, token.access_token);
    const membership = await readJson(membershipResponse);
    if (!membershipResponse.ok || membership?.state !== 'active') {
      console.error('GitHub organization membership check failed', {
        status: membershipResponse.status,
        state: membership?.state || null,
      });
      return redirectError(env, `Your GitHub account is not an active member of ${config(env).org}.`);
    }

    await auditLog(env, {
      eventType: 'LOGIN',
      githubId: me.id,
      username: me.login,
      displayName: me.name || me.login,
    });

    // Do not place a long-lived GitHub refresh token in the browser session.
    // The portal session is encrypted and short-lived; the user can re-authenticate
    // with GitHub when it expires. This avoids cross-site HttpOnly cookie problems
    // between github.io and workers.dev.
    const expiresIn = Math.min(Number(token.expires_in || 8 * 60 * 60), 8 * 60 * 60);
    const payload = {
      v: 2,
      iat: Date.now(),
      exp: Date.now() + expiresIn * 1000,
      ghToken: token.access_token,
      user: {
        id: me.id,
        login: me.login,
        name: me.name || me.login,
        avatar_url: me.avatar_url || '',
        html_url: me.html_url || '',
      },
    };
    const encrypted = await encryptJson(payload, env.SESSION_SECRET_HEX);

    const redirectUrl = new URL(config(env).frontendUrl + '/');
    redirectUrl.hash = `auth=${encodeURIComponent(encrypted)}`;

    const headers = new Headers({
      Location: redirectUrl.toString(),
      'Cache-Control': 'no-store',
    });
    headers.append(
      'Set-Cookie',
      cookie('skylark_oauth_state', '', {
        maxAge: 0,
        path: '/auth/callback',
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
      })
    );

    return new Response(null, { status: 302, headers });
  } catch (error) {
    console.error('OAuth callback error', {
      name: error?.name || 'Error',
      message: error?.message || String(error),
      stack: error?.stack || null,
    });
    return redirectError(env, 'Authentication failed unexpectedly. Please try again.');
  }
}

async function apiMe(request, env) {
  try {
    const result = await loadSession(request, env);
    if (!result.session) return withCors(json({ authenticated: false }, 401), request, env);

    // Validate the GitHub token itself so a revoked GitHub App authorization
    // cannot leave a stale portal session looking authenticated.
    const githubUserResponse = await githubFetch('/user', result.session.ghToken);
    if (githubUserResponse.status === 401) {
      return withCors(json({ authenticated: false, error: 'GitHub authorization is no longer valid. Please sign in again.' }, 401), request, env, { 'Set-Cookie': clearCookie() });
    }
    if (!githubUserResponse.ok) {
      return withCors(json({ authenticated: false, error: 'Could not validate the GitHub authorization.' }, 502), request, env);
    }

    const cfg = config(env);
    const lead = await isMspLead(result.session.ghToken, cfg.org, result.session.user?.login);
    const response = json({ authenticated: true, user: result.session.user, isLead: lead });
    return withCors(response, request, env, result.setCookie ? { 'Set-Cookie': result.setCookie } : {});
  } catch (error) {
    return withCors(json({ authenticated: false, error: error.message || 'Not authenticated.' }, 401), request, env, { 'Set-Cookie': clearCookie() });
  }
}

async function apiRepositories(request, env) {
  try {
    const result = await loadSession(request, env);
    if (!result.session) return withCors(json({ error: 'Not authenticated.' }, 401), request, env);
    const cfg = config(env);
    const repositories = [];
    for (const repo of cfg.repos) {
      const info = await hasRepoAccess(result.session.ghToken, cfg.org, repo);
      if (info) {
        repositories.push({
          name: repo,
          ...repoMeta(repo),
          default_branch: info.default_branch,
        });
      }
    }
    const response = json({ user: result.session.user, repositories });
    return withCors(response, request, env, result.setCookie ? { 'Set-Cookie': result.setCookie } : {});
  } catch (error) {
    return withCors(json({ error: error.message || 'Could not load repositories.' }, 401), request, env, { 'Set-Cookie': clearCookie() });
  }
}

async function apiTree(request, env, url) {
  try {
    const result = await loadSession(request, env);
    if (!result.session) return withCors(json({ error: 'Not authenticated.' }, 401), request, env);
    const cfg = config(env);
    const repo = url.searchParams.get('repo');
    if (!safeRepo(repo, cfg)) return withCors(json({ error: 'Invalid repository.' }, 400), request, env);

    const info = await hasRepoAccess(result.session.ghToken, cfg.org, repo);
    if (!info) return withCors(json({ error: 'Repository not accessible.' }, 403), request, env);

    const treeResponse = await githubFetch(
      `/repos/${encodeURIComponent(cfg.org)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(info.default_branch)}?recursive=1`,
      result.session.ghToken,
    );
    const tree = await readJson(treeResponse);
    if (!treeResponse.ok || !tree?.tree) return withCors(json({ error: 'Could not load repository tree.' }, 502), request, env);

    const baseFiles = tree.tree
      .filter((entry) => entry.type === 'blob' && isDocumentFile(entry.path))
      .map((entry) => ({
        path: entry.path,
        name: entry.path.split('/').pop(),
        size: entry.size || 0,
        sha: entry.sha,
      }));

    const history = await loadDocumentHistory(result.session.ghToken, cfg.org, repo, info.default_branch);
    const files = baseFiles.map((file) => ({
      ...file,
      ...documentMetadata(history, file),
    }));

    const metadataCount = files.filter((file) => file.creator).length;

    await auditLog(env, {
      eventType: 'KB_VIEW',
      githubId: result.session.user?.id,
      username: result.session.user?.login,
      displayName: result.session.user?.name,
      repo,
    });

    const response = json({
      repository: repo,
      files,
      metadataCount,
      metadataMissing: files.length - metadataCount,
      truncated: Boolean(tree.truncated),
    });
    return withCors(response, request, env, result.setCookie ? { 'Set-Cookie': result.setCookie } : {});
  } catch (error) {
    if (String(error?.message || '').includes('GitHub authorization is no longer valid')) {
      return withCors(json({ error: error.message }, 401), request, env, { 'Set-Cookie': clearCookie() });
    }
    return withCors(json({ error: error.message || 'Could not load document tree.' }, 500), request, env);
  }
}

async function apiFile(request, env, url) {
  try {
    const result = await loadSession(request, env);
    if (!result.session) return withCors(json({ error: 'Not authenticated.' }, 401), request, env);
    const cfg = config(env);
    const repo = url.searchParams.get('repo');
    const path = url.searchParams.get('path');
    if (!safeRepo(repo, cfg) || !safePath(path) || !isDocumentFile(path)) {
      return withCors(json({ error: 'Invalid document request.' }, 400), request, env);
    }

    const info = await hasRepoAccess(result.session.ghToken, cfg.org, repo);
    if (!info) return withCors(json({ error: 'Repository not accessible.' }, 403), request, env);

    const contentResponse = await githubFetch(
      `/repos/${encodeURIComponent(cfg.org)}/${encodeURIComponent(repo)}/contents/${path.split('/').map(encodeURIComponent).join('/')}?ref=${encodeURIComponent(info.default_branch)}`,
      result.session.ghToken,
      { headers: { Accept: 'application/vnd.github.raw+json' } },
    );
    if (!contentResponse.ok) return withCors(json({ error: 'Document could not be retrieved.' }, contentResponse.status === 404 ? 404 : 502), request, env);

    await auditLog(env, {
      eventType: 'DOCUMENT_VIEW',
      githubId: result.session.user?.id,
      username: result.session.user?.login,
      displayName: result.session.user?.name,
      repo,
      path,
      documentName: path.split('/').pop(),
    });

    const headers = new Headers();
    // Derive the MIME type from the requested path. GitHub raw-content responses
    // can advertise a generic content type for binary documents, which can make
    // browsers render a PDF as text.
    headers.set('Content-Type', mime(path));
    headers.set('Content-Disposition', `inline; filename="${path.split('/').pop().replaceAll('"', '')}"`);
    headers.set('Cache-Control', 'private, no-store');
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('Referrer-Policy', 'no-referrer');
    if (result.setCookie) headers.set('Set-Cookie', result.setCookie);
    const response = new Response(contentResponse.body, { status: 200, headers });
    return withCors(response, request, env);
  } catch (error) {
    if (String(error?.message || '').includes('GitHub authorization is no longer valid')) {
      return withCors(json({ error: error.message }, 401), request, env, { 'Set-Cookie': clearCookie() });
    }
    return withCors(json({ error: error.message || 'Could not retrieve document.' }, 500), request, env);
  }
}

function mime(path) {
  const lower = path.toLowerCase();
  if (lower.endsWith('.pdf')) return 'application/pdf';
  if (lower.endsWith('.png')) return 'image/png';
  if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'image/jpeg';
  if (lower.endsWith('.webp')) return 'image/webp';
  if (lower.endsWith('.md')) return 'text/markdown; charset=utf-8';
  if (lower.endsWith('.txt')) return 'text/plain; charset=utf-8';
  if (lower.endsWith('.docx')) return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  return 'application/octet-stream';
}

function health(request, env) {
  const missing = missingAuthConfig(env);
  return withCors(
    json({
      ok: missing.length === 0,
      missing,
      worker: 'msp-knowledge-api',
      auditDbBound: Boolean(env.DB),
    }),
    request,
    env
  );
}

async function logout(request, env) {
  try {
    const result = await loadSession(request, env);
    if (result.session) {
      await auditLog(env, {
        eventType: 'LOGOUT',
        githubId: result.session.user?.id,
        username: result.session.user?.login,
        displayName: result.session.user?.name,
      });
    }
  } catch (error) {
    // Logout must always succeed from the portal perspective.
    console.warn('Logout audit/session cleanup warning', {
      message: error?.message || String(error),
    });
  }

  return withCors(new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Set-Cookie': clearCookie(), 'Cache-Control': 'no-store' },
  }), request, env);
}

export default {
  async fetch(request, env) {
    try {
      if (request.method === 'OPTIONS') return options(request, env);
      const url = new URL(request.url);

      if (url.pathname === '/auth/login' && request.method === 'GET') return login(request, env);
      if (url.pathname === '/auth/callback' && request.method === 'GET') return callback(request, env);
      if (url.pathname === '/auth/logout' && request.method === 'POST') return logout(request, env);
      if (url.pathname === '/health' && request.method === 'GET') return health(request, env);
      if (url.pathname === '/api/me' && request.method === 'GET') return apiMe(request, env);
      if (url.pathname === '/api/repositories' && request.method === 'GET') return apiRepositories(request, env);
      if (url.pathname === '/api/tree' && request.method === 'GET') return apiTree(request, env, url);
      if (url.pathname === '/api/file' && request.method === 'GET') return apiFile(request, env, url);
      if (url.pathname === '/api/admin/audit' && request.method === 'GET') return apiAdminAudit(request, env, url);

      return json({ error: 'Not found.' }, 404, corsHeaders(request, env));
    } catch (error) {
      console.error('Unhandled worker error', error);
      return json({ error: 'Internal server error.' }, 500, corsHeaders(request, env));
    }
  },
};