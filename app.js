/**
 * Authelia users_database.yml admin UI — backend
 *
 * DEPLOYMENT REQUIREMENTS (do not skip):
 *  1. This runs in a Docker container behind a reverse-proxy container, so it
 *     binds to all interfaces (0.0.0.0) inside the container — that's normal
 *     and required for the proxy container to reach it over the Docker network.
 *     The isolation boundary is Docker Compose NOT publishing/exposing 8084 to
 *     the host — double check docker-compose.yml has no `ports: - "8084:8084"`
 *     for this service, only the reverse-proxy service should publish a port.
 *  2. Put it behind the same reverse proxy that enforces Authelia forward-auth
 *     (nginx/traefik `auth_request`/ForwardAuth), and require the "admins" group
 *     for this route in the Authelia access control rules.
 *  3. CRITICAL: the reverse proxy config MUST strip/overwrite any client-supplied
 *     `Remote-User` / `Remote-Groups` / `Remote-Name` / `Remote-Email` headers
 *     before setting the authoritative ones from Authelia. If the proxy passes
 *     through client headers unchanged, anyone can spoof admin access by simply
 *     sending `Remote-User: admin` / `Remote-Groups: admins` themselves.
 *  4. `npm install express-rate-limit` (added as a new dependency below).
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const yaml = require('js-yaml');
const fs = require('fs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { execFileSync } = require('child_process');
const os = require('os');
const path = require('path');
const upload = multer({ dest: '/tmp', limits: { fileSize: 25 * 1024 * 1024 } });

async function sendInvite(username) {
  const r = await fetch('http://authelia:9091/api/reset-password/identity/start', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Forwarded-Proto': 'https',
      'X-Forwarded-Host': 'auth.athenaeus.co.uk',
    },
    body: JSON.stringify({ username }),
  });
  if (!r.ok) throw new Error(`Authelia returned ${r.status}`);
}

const app = express();
const PORT = 8084;
const USERS_FILE = '/config/users_database.yml';

// Trust the reverse proxy for req.ip (needed for accurate rate limiting).
// Safe because Docker Compose keeps 8084 unpublished — only the proxy container can reach it (see above).
app.set('trust proxy', 1);

app.use(express.json({ limit: '16kb' })); // flag #6: cap body size
app.use(express.static('public', { index: 'index.html', dotfiles: 'deny' })); // flag: verify nothing sensitive lives in ./public

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------
const USERNAME_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const GROUP_RE = /^[a-zA-Z0-9_-]{1,64}$/;

function isValidUsername(name) {
  return typeof name === 'string' && USERNAME_RE.test(name);
}

function sanitizeGroups(groups) {
  if (!Array.isArray(groups)) return ['users'];
  const valid = groups.filter((g) => typeof g === 'string' && GROUP_RE.test(g));
  return valid.length ? valid : ['users'];
}

function logError(context, err) {
  // Full detail stays server-side only (flag #4).
  console.error(`[${new Date().toISOString()}] ${context}:`, err);
}

// ---------------------------------------------------------------------------
// YAML read/write — explicit JSON_SCHEMA so no custom/unsafe tags are ever
// resolved during load or emitted during dump (flag #3).
// ---------------------------------------------------------------------------
// ponytail: sync I/O fine for low-traffic admin tool; switch to fs.promises if >10 concurrent
function readUsers() {
  const content = fs.readFileSync(USERS_FILE, 'utf8');
  return yaml.load(content, { schema: yaml.JSON_SCHEMA }) || { users: {} };
}

// ponytail: no file locking; add lockfile if concurrent admin edits cause lost writes
function writeUsers(data) {
  fs.writeFileSync(
    USERS_FILE,
    yaml.dump(data, { lineWidth: -1, schema: yaml.JSON_SCHEMA }),
    'utf8'
  );
}

// ---------------------------------------------------------------------------
// Auth middleware (flag #1) — trusts Authelia forward-auth headers.
// ---------------------------------------------------------------------------
// ponytail: trusts proxy Remote-User header; if spoofing risk, add shared X-Auth-Token secret
function requireAuth(req, res, next) {
  const user = req.headers['remote-user'];
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const groupsHeader = req.headers['remote-groups'] || '';
  req.authUser = user;
  req.authGroups = groupsHeader
    .split(',')
    .map((g) => g.trim())
    .filter(Boolean);
  next();
}

function requireAdmin(req, res, next) {
  if (!req.authGroups.includes('admins')) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

// ---------------------------------------------------------------------------
// CSRF protection — double-submit cookie pattern (Critical #2 from frontend
// review). The cookie is unguessable and unreadable cross-origin, so a forged
// cross-site request can supply the auth cookie automatically but can't read
// or replay this token as a header.
// ---------------------------------------------------------------------------
function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (!key) return;
    try {
      out[key] = decodeURIComponent(val);
    } catch (e) {
      out[key] = val;
    }
  });
  return out;
}

app.get('/api/csrf-token', requireAuth, (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  res.cookie('csrf_token', token, {
    sameSite: 'strict',
    secure: req.secure,
    path: '/',
  });
  res.json({ token });
});

function requireCsrf(req, res, next) {
  const cookieToken = parseCookies(req.headers.cookie).csrf_token;
  const headerToken = req.headers['x-csrf-token'];
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: 'CSRF validation failed' });
  }
  next();
}

// ---------------------------------------------------------------------------
// Rate limiting (flag #5)
// ---------------------------------------------------------------------------
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});

const sensitiveLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later' },
});

app.use('/api', generalLimiter);

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
const PENDING_FILE = '/state/pending.json';

function readPending() {
  try {
    return JSON.parse(fs.readFileSync(PENDING_FILE, 'utf8'));
  } catch (e) {
    return {};
  }
}

function writePending(obj) {
  try {
    fs.writeFileSync(PENDING_FILE, JSON.stringify(obj));
  } catch (e) {
    logError('writePending', e);
  }
}

function markPending(username, hash) {
  const p = readPending();
  p[username] = hash;
  writePending(p);
}

function isPending(username, currentHash) {
  const p = readPending();
  return Object.prototype.hasOwnProperty.call(p, username) && p[username] === currentHash;
}

app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
  try {
    const data = readUsers();
    const users = Object.entries(data.users || {}).map(([username, info]) => ({
      username,
      displayname: info.displayname,
      email: info.email,
      disabled: info.disabled || false,
      pending: isPending(username, info.password),
      groups: info.groups || [],
    }));
    res.json(users);
  } catch (err) {
    logError('GET /api/users', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/users', requireAuth, requireCsrf, requireAdmin, async (req, res) => {
  try {
    const { username, displayname, email, password, groups } = req.body;
    if (!username || !displayname || !email) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (!isValidUsername(username)) {
      return res.status(400).json({
        error: 'Username must be 1-64 characters: letters, numbers, "_" or "-" only',
      });
    }
    if (password !== undefined && (typeof password !== 'string' || password.length < 8)) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    const data = readUsers();
    if (data.users[username]) {
      return res.status(400).json({ error: 'User already exists' });
    }
    const hash = await bcrypt.hash(password || crypto.randomBytes(32).toString('hex'), 12);
    data.users[username] = {
      disabled: false,
      displayname,
      password: hash,
      email,
      groups: sanitizeGroups(groups),
    };
    writeUsers(data);
    if (!password) {
      markPending(username, hash);
      try {
        await sendInvite(username);
      } catch (e) {
        logError('invite', e);
        return res.json({ success: true, invite: false });
      }
    }
    res.json({ success: true, invite: !password });
  } catch (err) {
    logError('POST /api/users', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/users/:username', requireAuth, requireCsrf, requireAdmin, (req, res) => {
  try {
    const { newUsername, displayname, email } = req.body;
    const data = readUsers();
    const user = data.users[req.params.username];
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (displayname) user.displayname = displayname;
    if (email) user.email = email;

    if (newUsername && newUsername !== req.params.username) {
      if (!isValidUsername(newUsername)) {
        return res.status(400).json({
          error: 'Username must be 1-64 characters: letters, numbers, "_" or "-" only',
        });
      }
      if (data.users[newUsername]) {
        return res.status(400).json({ error: 'Target username already exists' });
      }
      // ponytail: key order not preserved on rename — Authelia doesn't care
      data.users[newUsername] = data.users[req.params.username];
      delete data.users[req.params.username];
    }
    writeUsers(data);
    res.json({ success: true });
  } catch (err) {
    logError('PUT /api/users/:username', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/users/:username/invite', requireAuth, requireCsrf, requireAdmin, sensitiveLimiter, async (req, res) => {
  try {
    const data = readUsers();
    if (!data.users[req.params.username]) return res.status(404).json({ error: 'User not found' });
    markPending(req.params.username, data.users[req.params.username].password);
    await sendInvite(req.params.username);
    res.json({ success: true });
  } catch (err) {
    logError('POST /api/users/:username/invite', err);
    res.status(500).json({ error: 'Failed to send invite' });
  }
});

app.post('/api/import', requireAuth, requireCsrf, requireAdmin, sensitiveLimiter, upload.single('backup'), async (req, res) => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'imp-'));
  const cleanup = () => {
    try { fs.rmSync(work, { recursive: true, force: true }); } catch (e) {}
    if (req.file) { try { fs.unlinkSync(req.file.path); } catch (e) {} }
  };
  try {
    const passphrase = req.body.passphrase;
    if (!req.file || typeof passphrase !== 'string' || !passphrase) {
      cleanup();
      return res.status(400).json({ error: 'Backup file and passphrase are both required' });
    }
    const passFile = path.join(work, 'pp');
    fs.writeFileSync(passFile, passphrase, { mode: 0o600 });
    const tarPath = path.join(work, 'b.tar.gz');
    try {
      execFileSync('gpg', ['--batch', '--yes', '--quiet', '--decrypt', '--passphrase-file', passFile, '--output', tarPath, req.file.path], { stdio: 'pipe' });
    } catch (e) {
      cleanup();
      return res.status(400).json({ error: 'Could not decrypt - check the passphrase' });
    }
    try {
      execFileSync('tar', ['-xzf', tarPath, '-C', work, 'users_database.yml'], { stdio: 'pipe' });
    } catch (e) {
      cleanup();
      return res.status(400).json({ error: 'Archive did not contain a user database' });
    }
    const incoming = yaml.load(fs.readFileSync(path.join(work, 'users_database.yml'), 'utf8'), { schema: yaml.JSON_SCHEMA });
    if (!incoming || typeof incoming.users !== 'object') {
      cleanup();
      return res.status(400).json({ error: 'User database is not in the expected format' });
    }
    const data = readUsers();
    const added = [];
    const skipped = [];
    const failed = [];
    for (const [username, info] of Object.entries(incoming.users)) {
      if (!isValidUsername(username) || !info || !info.email) { failed.push(username); continue; }
      if (data.users[username]) { skipped.push(username); continue; }
      const hash = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 12);
      data.users[username] = {
        disabled: false,
        displayname: info.displayname || username,
        password: hash,
        email: info.email,
        groups: sanitizeGroups(info.groups),
      };
      added.push({ username, hash });
    }
    if (added.length) writeUsers(data);
    const invited = [];
    for (const { username, hash } of added) {
      markPending(username, hash);
      try {
        await sendInvite(username);
        invited.push(username);
      } catch (e) {
        logError('import invite ' + username, e);
      }
    }
    cleanup();
    res.json({ success: true, added: added.map((a) => a.username), invited, skipped, failed });
  } catch (err) {
    cleanup();
    logError('POST /api/import', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/users/:username/toggle', requireAuth, requireCsrf, requireAdmin, sensitiveLimiter, (req, res) => {
  try {
    const data = readUsers();
    const user = data.users[req.params.username];
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.disabled = !user.disabled;
    writeUsers(data);
    res.json({ success: true, disabled: user.disabled });
  } catch (err) {
    logError('PATCH /api/users/:username/toggle', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Password change: self-service requires proof of the current password;
// members of "admins" may reset any other user's password without it (flag #2).
app.patch('/api/users/:username/password', requireAuth, requireCsrf, sensitiveLimiter, async (req, res) => {
  try {
    const { password, oldPassword } = req.body;
    const targetUsername = req.params.username;
    const isAdmin = req.authGroups.includes('admins');
    const isSelf = req.authUser === targetUsername;

    if (!isAdmin && !isSelf) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const data = readUsers();
    const user = data.users[targetUsername];
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (isSelf && !isAdmin) {
      if (!oldPassword) {
        return res.status(400).json({ error: 'Current password required' });
      }
      const matches = await bcrypt.compare(oldPassword, user.password);
      if (!matches) {
        return res.status(403).json({ error: 'Current password is incorrect' });
      }
    }

    user.password = await bcrypt.hash(password, 12);
    writeUsers(data);
    res.json({ success: true });
  } catch (err) {
    logError('PATCH /api/users/:username/password', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/users/:username', requireAuth, requireCsrf, requireAdmin, sensitiveLimiter, (req, res) => {
  try {
    const data = readUsers();
    if (!data.users[req.params.username]) {
      return res.status(404).json({ error: 'User not found' });
    }
    delete data.users[req.params.username];
    writeUsers(data);
    const pend = readPending();
    if (Object.prototype.hasOwnProperty.call(pend, req.params.username)) {
      delete pend[req.params.username];
      writePending(pend);
    }
    res.json({ success: true });
  } catch (err) {
    logError('DELETE /api/users/:username', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => console.log(`Admin UI running on port ${PORT}`));
