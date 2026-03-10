#!/usr/bin/env node
// ╔══════════════════════════════════╗
// ║   GITDOCK  —  self-hosted        ║
// ║   Git + File vault over HTTP/S   ║
// ╚══════════════════════════════════╝

const express   = require('express');
const multer    = require('multer');
const path      = require('node:path');
const fs        = require('node:fs');
const crypto    = require('node:crypto');
const { execFileSync, spawn } = require('node:child_process');
const AdmZip    = require('adm-zip');

const app     = express();
const PORT    = process.env.PORT    || 3000;
const STORAGE = path.resolve(process.env.STORAGE_DIR || './storage');
const REPOS   = path.join(STORAGE, 'repos');
const FILES   = path.join(STORAGE, 'files');
const TMP     = path.join(STORAGE, 'tmp');
const USERS_FILE = path.join(STORAGE, 'users.json');

// ── bootstrap dirs ────────────────────────────────────────────────────────────
[STORAGE, REPOS, FILES, TMP].forEach(d => fs.mkdirSync(d, { recursive: true }));

// ── user store ────────────────────────────────────────────────────────────────
function loadUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch { return {}; }
}
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}
function hashPassword(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const key = crypto.scryptSync(pw, salt, 64).toString('hex');
  return salt + ':' + key;
}
function verifyPassword(pw, stored) {
  const [salt, key] = stored.split(':');
  const test = crypto.scryptSync(pw, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(key, 'hex'), Buffer.from(test, 'hex'));
}

// bootstrap default admin if no users exist
(function initUsers() {
  const users = loadUsers();
  if (Object.keys(users).length === 0) {
    users['admin'] = { hash: hashPassword('admin'), displayName: 'Admin', createdAt: Date.now() };
    saveUsers(users);
  }
})();

// ── session store (in-memory) ─────────────────────────────────────────────────
const sessions = {};
function createSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions[token] = { username, createdAt: Date.now() };
  return token;
}
function getSession(token) {
  return token ? sessions[token] || null : null;
}
function destroySession(token) {
  delete sessions[token];
}

const upload = multer({
  dest: TMP,
  limits: { fileSize: 500 * 1024 * 1024 },   // 500 MB
});

app.use(express.json());

// ── cookie parser (lightweight) ───────────────────────────────────────────────
app.use((req, _res, next) => {
  req.cookies = {};
  const hdr = req.headers.cookie || '';
  hdr.split(';').forEach(c => {
    const [k, ...v] = c.split('=');
    if (k) req.cookies[k.trim()] = decodeURIComponent(v.join('=').trim());
  });
  next();
});

// ── auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const session = getSession(req.cookies.session);
  if (session) { req.user = session.username; return next(); }
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Not authenticated' });
  return res.redirect('/login');
}

function optionalAuth(req, _res, next) {
  const session = getSession(req.cookies.session);
  if (session) req.user = session.username;
  next();
}

// ── helpers ───────────────────────────────────────────────────────────────────
function safeJoin(base, rel) {
  const resolved = path.resolve(base, rel);
  const norm = path.normalize(resolved);
  const baseWithSep = base.endsWith(path.sep) ? base : base + path.sep;
  if (norm !== base && !norm.startsWith(baseWithSep)) throw new Error('path traversal');
  return norm;
}

function sanitizeFilename(name) {
  return name.replace(/[/\\\0]/g, '_').replace(/^\.+/, '_');
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtSize(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 ** 3) return `${(b / 1024 ** 2).toFixed(1)} MB`;
  return `${(b / 1024 ** 3).toFixed(2)} GB`;
}

function dirSize(p) {
  let total = 0;
  try {
    for (const f of fs.readdirSync(p)) {
      const fp = path.join(p, f);
      const s = fs.statSync(fp);
      total += s.isDirectory() ? dirSize(fp) : s.size;
    }
  } catch {}
  return total;
}

// ── login page ────────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
  const session = getSession(req.cookies.session);
  if (session) return res.redirect('/');
  res.setHeader('Content-Type', 'text/html').send(LOGIN_HTML);
});

// ── auth API ──────────────────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  const users = loadUsers();
  const user = users[username.toLowerCase()];
  if (!user || !verifyPassword(password, user.hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = createSession(username.toLowerCase());
  res.setHeader('Set-Cookie', 'session=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800');
  res.json({ ok: true, username: username.toLowerCase(), displayName: user.displayName || username });
});

app.post('/api/auth/logout', (req, res) => {
  destroySession(req.cookies.session);
  res.setHeader('Set-Cookie', 'session=; Path=/; HttpOnly; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const users = loadUsers();
  const u = users[req.user];
  if (!u) return res.status(404).json({ error: 'User not found' });
  res.json({ username: req.user, displayName: u.displayName || req.user });
});

app.post('/api/auth/password', requireAuth, (req, res) => {
  const { current, newPassword } = req.body || {};
  if (!current || !newPassword) return res.status(400).json({ error: 'Missing fields' });
  if (newPassword.length < 3) return res.status(400).json({ error: 'Password too short' });
  const users = loadUsers();
  const u = users[req.user];
  if (!u || !verifyPassword(current, u.hash)) return res.status(401).json({ error: 'Wrong current password' });
  u.hash = hashPassword(newPassword);
  saveUsers(users);
  // destroy all sessions for this user
  Object.keys(sessions).forEach(t => { if (sessions[t].username === req.user) delete sessions[t]; });
  res.json({ ok: true });
});

app.post('/api/auth/profile', requireAuth, (req, res) => {
  const { displayName } = req.body || {};
  if (!displayName || !displayName.trim()) return res.status(400).json({ error: 'Empty name' });
  const users = loadUsers();
  if (!users[req.user]) return res.status(404).json({ error: 'User not found' });
  users[req.user].displayName = displayName.trim();
  saveUsers(users);
  res.json({ ok: true, displayName: displayName.trim() });
});

// ── protected frontend ────────────────────────────────────────────────────────
app.get('/', requireAuth, (req, res) => res.setHeader('Content-Type', 'text/html').send(HTML));

// ── protected API routes ──────────────────────────────────────────────────────
app.use('/api/repos', requireAuth);
app.use('/api/info', requireAuth);

// ── API: repos ────────────────────────────────────────────────────────────────
app.get('/api/repos', (_req, res) => {
  const repos = fs.readdirSync(REPOS)
    .filter(r => r.endsWith('.git'))
    .map(r => {
      const rp = path.join(REPOS, r);
      let lastCommit = null;
      try {
        lastCommit = execFileSync('git', ['--git-dir', rp, 'log', '-1', '--format=%ar — %s'], { encoding: 'utf8' }).trim();
      } catch {}
      return { name: r, size: fmtSize(dirSize(rp)), lastCommit };
    });
  res.json(repos);
});

app.post('/api/repos', (req, res) => {
  let { name } = req.body || {};
  if (!name || !/^[\w.\-]+$/.test(name)) return res.status(400).json({ error: 'Invalid repo name' });
  if (!name.endsWith('.git')) name += '.git';
  const rp = path.join(REPOS, name);
  if (fs.existsSync(rp)) return res.status(409).json({ error: 'Repo already exists' });
  execFileSync('git', ['init', '--bare', rp]);
  execFileSync('git', ['--git-dir', rp, 'config', 'http.receivepack', 'true']);
  res.json({ name, cloneUrl: `http://HOST/git/${name}` });
});

app.delete('/api/repos/:name', (req, res) => {
  try {
    const rp = safeJoin(REPOS, req.params.name);
    if (!fs.existsSync(rp)) return res.status(404).end();
    fs.rmSync(rp, { recursive: true, force: true });
    res.json({ ok: true });
  } catch { res.status(400).end(); }
});

// ── API: repo branches ───────────────────────────────────────────────────────
app.get('/api/repos/:name/branches', (req, res) => {
  try {
    const rp = safeJoin(REPOS, req.params.name);
    if (!fs.existsSync(rp)) return res.status(404).json({ error: 'Repo not found' });
    let branches = [];
    try {
      const out = execFileSync('git', ['--git-dir', rp, 'for-each-ref',
        '--format=%(refname:short)\t%(objectname:short)\t%(committerdate:relative)\t%(subject)',
        'refs/heads/'], { encoding: 'utf8' });
      branches = out.trim().split('\n').filter(Boolean).map(line => {
        const [name, hash, date, ...rest] = line.split('\t');
        return { name, hash, date, subject: rest.join('\t') };
      });
    } catch {}
    let head = null;
    try {
      head = execFileSync('git', ['--git-dir', rp, 'symbolic-ref', '--short', 'HEAD'],
        { encoding: 'utf8' }).trim();
    } catch {}
    res.json({ branches, head });
  } catch { res.status(400).end(); }
});

// ── API: commit log ──────────────────────────────────────────────────────────
app.get('/api/repos/:name/log', (req, res) => {
  try {
    const rp = safeJoin(REPOS, req.params.name);
    if (!fs.existsSync(rp)) return res.status(404).json({ error: 'Repo not found' });
    const ref = req.query.ref || 'HEAD';
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const skip = Math.max(parseInt(req.query.skip) || 0, 0);
    let commits = [];
    try {
      const out = execFileSync('git', ['--git-dir', rp, 'log', ref,
        `--max-count=${limit}`, `--skip=${skip}`,
        '--format=%H%x09%h%x09%an%x09%ae%x09%at%x09%s',
        '--'], { encoding: 'utf8' });
      commits = out.trim().split('\n').filter(Boolean).map(line => {
        const [hash, shortHash, author, email, ts, ...rest] = line.split('\t');
        return { hash, shortHash, author, email, timestamp: parseInt(ts) * 1000, subject: rest.join('\t') };
      });
    } catch {}
    res.json({ commits });
  } catch { res.status(400).end(); }
});

// ── API: commit detail (files changed + stats) ──────────────────────────────
app.get('/api/repos/:name/commit/:hash', (req, res) => {
  try {
    const rp = safeJoin(REPOS, req.params.name);
    if (!fs.existsSync(rp)) return res.status(404).json({ error: 'Repo not found' });
    const hash = req.params.hash.replace(/[^a-f0-9]/gi, '').slice(0, 40);
    if (!hash) return res.status(400).json({ error: 'Invalid hash' });

    // commit info
    const info = execFileSync('git', ['--git-dir', rp, 'log', '-1',
      '--format=%H%x09%h%x09%an%x09%ae%x09%at%x09%s%x09%b', hash, '--'],
      { encoding: 'utf8' }).trim();
    const [fullHash, shortHash, author, email, ts, subject, ...bodyParts] = info.split('\t');
    const body = bodyParts.join('\t').trim();

    // files changed with status
    let files = [];
    try {
      const out = execFileSync('git', ['--git-dir', rp, 'diff-tree', '-r', '--root', '--no-commit-id',
        '--name-status', '-M', hash, '--'], { encoding: 'utf8' });
      files = out.trim().split('\n').filter(Boolean).map(line => {
        const parts = line.split('\t');
        const status = parts[0][0]; // A/M/D/R/C
        const file = parts.length > 2 ? parts[2] : parts[1]; // renamed: old\tnew
        const oldFile = parts.length > 2 ? parts[1] : null;
        return { status, file, oldFile };
      });
    } catch {}

    // numstat for additions/deletions
    let stats = {};
    try {
      const out = execFileSync('git', ['--git-dir', rp, 'diff-tree', '-r', '--root', '--no-commit-id',
        '--numstat', '-M', hash, '--'], { encoding: 'utf8' });
      out.trim().split('\n').filter(Boolean).forEach(line => {
        const [add, del, ...fp] = line.split('\t');
        const f = fp.join('\t').replace(/.*=> /, '').replace(/[{}]/g, '').trim();
        stats[f] = { additions: add === '-' ? 0 : parseInt(add), deletions: del === '-' ? 0 : parseInt(del) };
      });
    } catch {}

    files = files.map(f => ({ ...f, additions: (stats[f.file] || {}).additions || 0, deletions: (stats[f.file] || {}).deletions || 0 }));

    res.json({
      hash: fullHash, shortHash, author, email,
      timestamp: parseInt(ts) * 1000, subject, body,
      files, totalFiles: files.length,
      totalAdditions: files.reduce((s, f) => s + f.additions, 0),
      totalDeletions: files.reduce((s, f) => s + f.deletions, 0)
    });
  } catch(e) { res.status(400).json({ error: e.message }); }
});

// ── API: commit file diff ────────────────────────────────────────────────────
app.get('/api/repos/:name/diff/:hash', (req, res) => {
  try {
    const rp = safeJoin(REPOS, req.params.name);
    if (!fs.existsSync(rp)) return res.status(404).json({ error: 'Repo not found' });
    const hash = req.params.hash.replace(/[^a-f0-9]/gi, '').slice(0, 40);
    const file = req.query.file;
    if (!hash || !file) return res.status(400).json({ error: 'Missing params' });

    let diff = '';
    try {
      diff = execFileSync('git', ['--git-dir', rp, 'diff', `${hash}~1`, hash, '--', file],
        { encoding: 'utf8', maxBuffer: 1024 * 1024 });
    } catch {
      try {
        // first commit has no parent
        diff = execFileSync('git', ['--git-dir', rp, 'diff', '--no-index', '/dev/null', file],
          { encoding: 'utf8', maxBuffer: 1024 * 1024 }).replace(/\/dev\/null/g, 'a/' + file);
      } catch {
        try {
          diff = execFileSync('git', ['--git-dir', rp, 'show', `${hash}:${file}`],
            { encoding: 'utf8', maxBuffer: 1024 * 1024 });
          diff = diff.split('\n').map(l => '+' + l).join('\n');
        } catch { diff = '(binary file or unavailable)'; }
      }
    }
    res.json({ diff });
  } catch(e) { res.status(400).json({ error: e.message }); }
});

// ── API: repo tree ───────────────────────────────────────────────────────────
app.get('/api/repos/:name/tree', (req, res) => {
  try {
    const rp = safeJoin(REPOS, req.params.name);
    if (!fs.existsSync(rp)) return res.status(404).json({ error: 'Repo not found' });
    const ref = req.query.ref || 'HEAD';
    const treePath = req.query.path || '';
    if (ref.startsWith('-') || ref.includes('..')) return res.status(400).json({ error: 'Invalid ref' });
    if (treePath.startsWith('-') || treePath.includes('..')) return res.status(400).json({ error: 'Invalid path' });
    let items = [];
    try {
      const target = treePath ? `${ref}:${treePath}` : ref;
      const out = execFileSync('git', ['--git-dir', rp, 'ls-tree', '-l', target],
        { encoding: 'utf8' });
      items = out.trim().split('\n').filter(Boolean).map(line => {
        const m = line.match(/^(\d+)\s+(blob|tree)\s+([a-f0-9]+)\s+(-|\d+)\t(.+)$/);
        if (!m) return null;
        return { mode: m[1], type: m[2], hash: m[3], size: m[4] === '-' ? null : parseInt(m[4]), name: m[5] };
      }).filter(Boolean);
      items.sort((a, b) => {
        if (a.type === 'tree' && b.type !== 'tree') return -1;
        if (a.type !== 'tree' && b.type === 'tree') return 1;
        return a.name.localeCompare(b.name);
      });
    } catch {}
    res.json(items);
  } catch { res.status(400).end(); }
});

// ── API: repo blob ───────────────────────────────────────────────────────────
app.get('/api/repos/:name/blob', (req, res) => {
  try {
    const rp = safeJoin(REPOS, req.params.name);
    if (!fs.existsSync(rp)) return res.status(404).json({ error: 'Repo not found' });
    const ref = req.query.ref || 'HEAD';
    const filePath = req.query.path;
    if (!filePath) return res.status(400).json({ error: 'path required' });
    if (ref.startsWith('-') || ref.includes('..')) return res.status(400).json({ error: 'Invalid ref' });
    if (filePath.startsWith('-') || filePath.includes('..')) return res.status(400).json({ error: 'Invalid path' });
    try {
      const buf = execFileSync('git', ['--git-dir', rp, 'show', `${ref}:${filePath}`],
        { maxBuffer: 5 * 1024 * 1024 });
      const isBinary = buf.slice(0, 8192).includes(0);
      if (isBinary) {
        res.json({ content: null, path: filePath, binary: true, size: buf.length });
      } else {
        res.json({ content: buf.toString('utf8'), path: filePath, binary: false });
      }
    } catch {
      res.json({ content: null, path: filePath, binary: true });
    }
  } catch { res.status(400).json({ error: 'Could not read file' }); }
});

// ── API: raw file (for media preview) ────────────────────────────────────────
app.get('/api/repos/:name/raw', (req, res) => {
  try {
    const rp = safeJoin(REPOS, req.params.name);
    if (!fs.existsSync(rp)) return res.status(404).end();
    const ref = req.query.ref || 'HEAD';
    const filePath = req.query.path;
    if (!filePath) return res.status(400).end();
    if (ref.startsWith('-') || ref.includes('..')) return res.status(400).end();
    if (filePath.startsWith('-') || filePath.includes('..')) return res.status(400).end();
    const buf = execFileSync('git', ['--git-dir', rp, 'show', `${ref}:${filePath}`],
      { maxBuffer: 50 * 1024 * 1024 });
    const ext = path.extname(filePath).toLowerCase().slice(1);
    const mimeMap = {
      png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', gif:'image/gif',
      webp:'image/webp', svg:'image/svg+xml', bmp:'image/bmp', ico:'image/x-icon',
      avif:'image/avif', mp4:'video/mp4', webm:'video/webm', mov:'video/quicktime',
      avi:'video/x-msvideo', mp3:'audio/mpeg', wav:'audio/wav', ogg:'audio/ogg',
      flac:'audio/flac', aac:'audio/aac', m4a:'audio/mp4', pdf:'application/pdf',
    };
    res.setHeader('Content-Type', mimeMap[ext] || 'application/octet-stream');
    res.setHeader('Content-Length', buf.length);
    res.send(buf);
  } catch { res.status(400).end(); }
});

// ── API: web commit ──────────────────────────────────────────────────────────
app.post('/api/repos/:name/commit', upload.array('files', 100), (req, res) => {
  const tmpDir = path.join(TMP, 'commit-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8));
  try {
    const rp = safeJoin(REPOS, req.params.name);
    if (!fs.existsSync(rp)) return res.status(404).json({ error: 'Repo not found' });
    const branch = req.body.branch || 'main';
    const message = req.body.message || 'Web upload';
    if (!/^[\w.\-/]+$/.test(branch)) return res.status(400).json({ error: 'Invalid branch name' });
    const files = req.files;
    if (!files || !files.length) return res.status(400).json({ error: 'No files' });
    const prefix = req.body.prefix || '';
    if (prefix && (prefix.startsWith('/') || prefix.startsWith('-') || prefix.includes('..'))) {
      return res.status(400).json({ error: 'Invalid path prefix' });
    }

    execFileSync('git', ['clone', rp, tmpDir], { stdio: 'pipe' });
    try {
      execFileSync('git', ['-C', tmpDir, 'checkout', branch], { stdio: 'pipe' });
    } catch {
      try {
        execFileSync('git', ['-C', tmpDir, 'checkout', '-b', branch], { stdio: 'pipe' });
      } catch {
        execFileSync('git', ['-C', tmpDir, 'checkout', '--orphan', branch], { stdio: 'pipe' });
      }
    }

    for (const f of files) {
      const safeName = sanitizeFilename(Buffer.from(f.originalname, 'latin1').toString('utf8'));
      const relPath = prefix ? path.join(prefix, safeName) : safeName;
      const destPath = safeJoin(tmpDir, relPath);
      fs.mkdirSync(path.dirname(destPath), { recursive: true });
      fs.copyFileSync(f.path, destPath);
    }

    execFileSync('git', ['-C', tmpDir, 'add', '.'], { stdio: 'pipe' });
    execFileSync('git', ['-C', tmpDir, '-c', 'user.name=GitDock Web', '-c', 'user.email=web@gitdock', 'commit', '-m', message], { stdio: 'pipe' });
    execFileSync('git', ['-C', tmpDir, 'push', 'origin', branch], { stdio: 'pipe' });
    res.json({ ok: true, branch, message });
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    if (req.files) req.files.forEach(f => { try { fs.unlinkSync(f.path); } catch {} });
  }
});

// ── API: files (kept for API access) ─────────────────────────────────────────
app.get('/api/files', (_req, res) => {
  const items = fs.readdirSync(FILES).map(f => {
    const fp = path.join(FILES, f);
    const s  = fs.statSync(fp);
    return {
      name:  f,
      size:  fmtSize(s.isDirectory() ? dirSize(fp) : s.size),
      isDir: s.isDirectory(),
      mtime: s.mtime,
    };
  });
  res.json(items);
});

app.post('/api/upload', upload.single('file'), (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'No file received' });

  const origName = sanitizeFilename(Buffer.from(file.originalname, 'latin1').toString('utf8'));
  const doExtract = req.body.extract === 'true';

  try {
    if (doExtract && origName.toLowerCase().endsWith('.zip')) {
      const zip     = new AdmZip(file.path);
      const dirName = path.basename(origName, '.zip');
      const destDir = safeJoin(FILES, dirName);
      for (const entry of zip.getEntries()) {
        const entryTarget = path.resolve(destDir, entry.entryName);
        if (!entryTarget.startsWith(destDir + path.sep) && entryTarget !== destDir) {
          fs.unlinkSync(file.path);
          return res.status(400).json({ error: 'Zip contains unsafe path: ' + entry.entryName });
        }
      }
      zip.extractAllTo(destDir, true);
      fs.unlinkSync(file.path);
      res.json({ type: 'extracted', name: path.basename(destDir) });
    } else {
      const dest = safeJoin(FILES, origName);
      fs.renameSync(file.path, dest);
      res.json({ type: 'saved', name: origName });
    }
  } catch (err) {
    try { fs.unlinkSync(file.path); } catch {}
    res.status(500).json({ error: String(err) });
  }
});

app.delete('/api/files/:name', (req, res) => {
  try {
    const fp = safeJoin(FILES, req.params.name);
    if (!fs.existsSync(fp)) return res.status(404).end();
    fs.rmSync(fp, { recursive: true, force: true });
    res.json({ ok: true });
  } catch { res.status(400).end(); }
});

app.get('/api/files/:name/download', (req, res) => {
  try {
    const fp = safeJoin(FILES, req.params.name);
    if (!fs.existsSync(fp)) return res.status(404).end();
    if (fs.statSync(fp).isDirectory()) {
      const zip = new AdmZip();
      zip.addLocalFolder(fp);
      const safeName = encodeURIComponent(req.params.name).replace(/%20/g, '+');
      res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${safeName}.zip`);
      res.setHeader('Content-Type', 'application/zip');
      res.send(zip.toBuffer());
    } else {
      res.download(fp);
    }
  } catch { res.status(400).end(); }
});

// ── Git smart HTTP backend ────────────────────────────────────────────────────
app.all('/git/{*path}', (req, res) => {
  const pathInfo = req.path.replace(/^\/git/, '');
  const isPush = pathInfo.includes('git-receive-pack');

  // Require Basic auth for push operations
  let remoteUser = '';
  if (isPush) {
    const authHeader = req.headers.authorization || '';
    if (!authHeader.startsWith('Basic ')) {
      res.setHeader('WWW-Authenticate', 'Basic realm="GitDock"');
      return res.status(401).send('Authentication required');
    }
    const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
    const colon = decoded.indexOf(':');
    if (colon === -1) { res.setHeader('WWW-Authenticate', 'Basic realm="GitDock"'); return res.status(401).send('Invalid credentials'); }
    const username = decoded.slice(0, colon).toLowerCase();
    const password = decoded.slice(colon + 1);
    const users = loadUsers();
    const user = users[username];
    if (!user || !verifyPassword(password, user.hash)) {
      res.setHeader('WWW-Authenticate', 'Basic realm="GitDock"');
      return res.status(401).send('Invalid credentials');
    }
    remoteUser = username;
  }

  const repoMatch = pathInfo.match(/^\/([\w.\-]+\.git)\//);
  if (repoMatch) {
    const rp = path.join(REPOS, repoMatch[1]);
    if (!fs.existsSync(rp)) {
      try {
        execFileSync('git', ['init', '--bare', rp]);
        execFileSync('git', ['--git-dir', rp, 'config', 'http.receivepack', 'true']);
      } catch (e) {
        return res.status(500).send('Could not initialise repo');
      }
    }
  }

  const qs = Object.entries(req.query).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');

  const env = {
    ...process.env,
    GIT_PROJECT_ROOT:  REPOS,
    GIT_HTTP_EXPORT_ALL: '1',
    PATH_INFO:         pathInfo,
    REMOTE_USER:       remoteUser,
    REMOTE_ADDR:       req.ip || '',
    CONTENT_TYPE:      req.headers['content-type'] || '',
    QUERY_STRING:      qs,
    REQUEST_METHOD:    req.method,
    SERVER_PROTOCOL:   'HTTP/1.1',
    HTTP_GIT_PROTOCOL: req.headers['git-protocol'] || '',
  };

  const git = spawn('git', ['http-backend'], { env });
  req.pipe(git.stdin);

  let raw = Buffer.alloc(0);
  let headersDone = false;

  git.stdout.on('data', chunk => {
    if (headersDone) { res.write(chunk); return; }
    raw = Buffer.concat([raw, chunk]);
    const sep = raw.indexOf('\r\n\r\n');
    if (sep === -1) return;

    headersDone = true;
    const headerBlock = raw.slice(0, sep).toString('utf8');
    const body        = raw.slice(sep + 4);

    let status = 200;
    headerBlock.split('\r\n').forEach(line => {
      const sm = line.match(/^Status:\s*(\d+)/i);
      if (sm) { status = parseInt(sm[1]); return; }
      const ci = line.indexOf(': ');
      if (ci > 0) res.setHeader(line.slice(0, ci), line.slice(ci + 2));
    });
    res.status(status);
    if (body.length) res.write(body);
  });

  git.stdout.on('end', () => res.end());
  git.stderr.on('data', d => process.stderr.write('[git] ' + d));
  git.on('error', err => { console.error('[spawn]', err); if (!res.headersSent) res.status(500).end(); });
});

// ── API: system info ──────────────────────────────────────────────────────────
app.get('/api/info', (_req, res) => {
  res.json({
    repos:     fs.readdirSync(REPOS).filter(r => r.endsWith('.git')).length,
    files:     fs.readdirSync(FILES).length,
    storageMB: (dirSize(STORAGE) / 1024 / 1024).toFixed(1),
    uptime:    Math.floor(process.uptime()),
  });
});

// ═════════════════════════════════════════════════════════════════════════════
//  LOGIN PAGE
// ═════════════════════════════════════════════════════════════════════════════
const LOGIN_HTML = /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GitDock — Login</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Space+Grotesk:wght@300;500;700&display=swap" rel="stylesheet">
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{--bg:#000;--bg1:#080808;--a:#00e5a0;--a2:#0ea5e9;--txt:#d4d4d4;--txt2:#666;--mono:'JetBrains Mono',monospace;--sans:'Space Grotesk',sans-serif;--r:8px;--danger:#ff3355}
  html,body{height:100%}
  body{background:var(--bg);color:var(--txt);font-family:var(--sans);display:flex;align-items:center;justify-content:center;overflow:hidden}

  .login-wrapper{width:100%;max-width:380px;padding:0 24px}

  .login-brand{text-align:center;margin-bottom:48px}
  .login-dot{width:10px;height:10px;border-radius:50%;background:var(--a);display:inline-block;margin-right:8px;box-shadow:0 0 12px rgba(0,229,160,.4);animation:pulse 2s ease-in-out infinite}
  .login-title{font-family:var(--mono);font-size:clamp(20px,1.6rem,28px);font-weight:700;letter-spacing:3px;color:var(--txt);display:inline}
  @keyframes pulse{0%,100%{box-shadow:0 0 12px rgba(0,229,160,.4)}50%{box-shadow:0 0 24px rgba(0,229,160,.7)}}

  .login-card{background:#060606;border:1px solid rgba(255,255,255,.04);border-radius:16px;padding:clamp(28px,3vw,40px);position:relative;overflow:hidden}
  .login-card::before{content:'';position:absolute;top:0;left:50%;transform:translateX(-50%);width:60%;height:1px;background:linear-gradient(90deg,transparent,rgba(0,229,160,.3),transparent)}

  .login-subtitle{font-family:var(--mono);font-size:12px;color:var(--txt2);letter-spacing:1px;text-transform:uppercase;margin-bottom:28px;text-align:center}

  .field{margin-bottom:20px}
  .field label{display:block;font-family:var(--mono);font-size:11px;color:var(--txt2);letter-spacing:.5px;text-transform:uppercase;margin-bottom:6px}
  .field input{width:100%;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:12px 14px;font-family:var(--mono);font-size:14px;color:var(--txt);outline:none;transition:border-color .2s,box-shadow .2s}
  .field input:focus{border-color:rgba(0,229,160,.3);box-shadow:0 0 0 3px rgba(0,229,160,.06)}
  .field input::placeholder{color:var(--txt2);opacity:.5}

  .login-btn{width:100%;padding:13px;background:var(--a);color:#000;font-family:var(--mono);font-size:14px;font-weight:600;letter-spacing:1px;border:none;border-radius:10px;cursor:pointer;transition:all .3s cubic-bezier(.22,1,.36,1);margin-top:8px;text-transform:uppercase}
  .login-btn:hover{box-shadow:0 0 24px rgba(0,229,160,.3);transform:translateY(-1px)}
  .login-btn:active{transform:translateY(0)}
  .login-btn:disabled{opacity:.4;cursor:not-allowed;transform:none;box-shadow:none}

  .login-error{margin-top:16px;padding:10px 14px;background:rgba(255,51,85,.06);border:1px solid rgba(255,51,85,.15);border-radius:8px;color:var(--danger);font-family:var(--mono);font-size:12px;text-align:center;display:none}
  .login-error.show{display:block;animation:shake .3s ease-in-out}
  @keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-5px)}75%{transform:translateX(5px)}}

  .login-footer{text-align:center;margin-top:32px;font-family:var(--mono);font-size:11px;color:var(--txt2);opacity:.4}

  .glow-orb{position:fixed;border-radius:50%;filter:blur(80px);opacity:.06;pointer-events:none;z-index:-1}
  .glow-orb.g1{width:300px;height:300px;background:var(--a);top:20%;left:10%}
  .glow-orb.g2{width:200px;height:200px;background:var(--a2);bottom:15%;right:15%}
</style>
</head>
<body>
<div class="glow-orb g1"></div>
<div class="glow-orb g2"></div>

<div class="login-wrapper">
  <div class="login-brand">
    <span class="login-dot"></span><span class="login-title">GITDOCK</span>
  </div>

  <div class="login-card">
    <div class="login-subtitle">Sign in to continue</div>
    <form id="login-form" autocomplete="on">
      <div class="field">
        <label for="l-user">Username</label>
        <input id="l-user" name="username" type="text" placeholder="admin" autocomplete="username" autofocus required>
      </div>
      <div class="field">
        <label for="l-pass">Password</label>
        <input id="l-pass" name="password" type="password" placeholder="••••••" autocomplete="current-password" required>
      </div>
      <button type="submit" class="login-btn" id="login-btn">Sign in</button>
    </form>
    <div class="login-error" id="login-error"></div>
  </div>

  <div class="login-footer">self-hosted git vault</div>
</div>

<script>
document.getElementById('login-form').addEventListener('submit', function(e) {
  e.preventDefault();
  var btn = document.getElementById('login-btn');
  var err = document.getElementById('login-error');
  var user = document.getElementById('l-user').value.trim();
  var pass = document.getElementById('l-pass').value;
  if (!user || !pass) return;
  btn.disabled = true;
  btn.textContent = 'Signing in\\u2026';
  err.classList.remove('show');
  fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: user, password: pass })
  }).then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
    .then(function(r) {
      if (r.ok) { window.location.href = '/'; }
      else { err.textContent = r.data.error || 'Login failed'; err.classList.add('show'); }
    })
    .catch(function() { err.textContent = 'Connection error'; err.classList.add('show'); })
    .finally(function() { btn.disabled = false; btn.textContent = 'Sign in'; });
});
</script>
</body>
</html>`;

// ═════════════════════════════════════════════════════════════════════════════
//  AMOLED FRONTEND  —  pure black, neon teal accent
// ═════════════════════════════════════════════════════════════════════════════
const HTML = /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GitDock</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Space+Grotesk:wght@300;500;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:      #000000;
    --bg1:     #080808;
    --bg2:     #0f0f0f;
    --bg3:     #161616;
    --border:  #1c1c1c;
    --border2: #282828;
    --a:       #00e5a0;
    --a2:      #0ea5e9;
    --a3:      #a855f7;
    --danger:  #ff3355;
    --warn:    #f59e0b;
    --txt:     #d4d4d4;
    --txt2:    #666;
    --txt3:    #333;
    --mono:    'JetBrains Mono', monospace;
    --sans:    'Space Grotesk', sans-serif;
    --r:       6px;
    --r2:      12px;
    --glow:    0 0 20px rgba(0,229,160,.15);
    --glowb:   0 0 20px rgba(14,165,233,.15);
  }
  *, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
  html { scroll-behavior:smooth; font-size:clamp(14px, 0.45vw + 12px, 20px); }
  body {
    background: var(--bg);
    color: var(--txt);
    font-family: var(--sans);
    font-size: 1rem;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* ── scrollbar ── */
  ::-webkit-scrollbar { width:6px; height:6px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border2); border-radius:3px; }

  /* ── topbar ── */
  #topbar {
    position:fixed; top:clamp(12px, 1vw, 22px); left:50%; transform:translateX(-50%); z-index:100;
    display:flex; align-items:center; gap:clamp(14px, 1.1vw, 24px);
    padding: clamp(8px, .6vw, 14px) clamp(20px, 1.6vw, 36px);
    background: rgba(0,0,0,.92);
    backdrop-filter: blur(20px);
    border: 1px solid rgba(255,255,255,.05);
    border-radius: 999px;
    transition: border-color .3s;
  }
  #topbar:hover { border-color: rgba(255,255,255,.09); }
  .logo {
    font-family: var(--mono);
    font-size: clamp(11px, 0.75rem, 15px);
    font-weight: 600;
    letter-spacing: 3px;
    color: var(--txt2);
    text-transform: uppercase;
    display:flex; align-items:center; gap:8px;
    cursor:pointer;
    user-select:none; -webkit-user-select:none;
    transition: color .3s ease;
  }
  .logo:hover { color:var(--txt); }
  .logo-dot { width:clamp(5px,.4rem,8px);height:clamp(5px,.4rem,8px);border-radius:50%;background:var(--a); animation: pulse 2s ease-in-out infinite; }
  @keyframes pulse { 0%,100%{opacity:1;} 50%{opacity:.4;} }

  /* ── animations ── */
  @keyframes fadeSlideUp {
    from { opacity:0; transform:translateY(12px); }
    to   { opacity:1; transform:translateY(0); }
  }
  @keyframes fadeSlideDown {
    from { opacity:0; transform:translateY(-10px); }
    to   { opacity:1; transform:translateY(0); }
  }
  @keyframes fadeSlideLeft {
    from { opacity:0; transform:translateX(20px); }
    to   { opacity:1; transform:translateX(0); }
  }
  @keyframes fadeSlideRight {
    from { opacity:0; transform:translateX(-20px); }
    to   { opacity:1; transform:translateX(0); }
  }
  @keyframes fadeIn {
    from { opacity:0; }
    to   { opacity:1; }
  }
  @keyframes scaleIn {
    from { opacity:0; transform:scale(.96); }
    to   { opacity:1; transform:scale(1); }
  }
  @keyframes iconBounce {
    0%,100% { transform:translateY(0); }
    40% { transform:translateY(-3px); }
    60% { transform:translateY(1px); }
  }
  @keyframes iconWiggle {
    0%,100% { transform:rotate(0deg); }
    25% { transform:rotate(-8deg); }
    75% { transform:rotate(8deg); }
  }
  @keyframes iconPop {
    0%   { transform:scale(1); }
    50%  { transform:scale(1.2); }
    100% { transform:scale(1); }
  }

  /* view transitions */
  #main-view.anim-in   { animation: fadeSlideUp .28s cubic-bezier(.22,1,.36,1) both; }
  #detail-view.anim-in { animation: fadeSlideLeft .3s cubic-bezier(.22,1,.36,1) both; }
  #main-view.anim-out  { animation: fadeIn .15s ease reverse both; }

  /* tab panel animation */
  .tab-panel.anim-in { animation: fadeSlideUp .25s cubic-bezier(.22,1,.36,1) both; }

  /* tree items stagger */
  .tree-item.anim-in { animation: fadeSlideUp .22s cubic-bezier(.22,1,.36,1) both; }
  .tree-list.anim-in .tree-item:nth-child(1)  { animation-delay: 0ms; }
  .tree-list.anim-in .tree-item:nth-child(2)  { animation-delay: 25ms; }
  .tree-list.anim-in .tree-item:nth-child(3)  { animation-delay: 50ms; }
  .tree-list.anim-in .tree-item:nth-child(4)  { animation-delay: 65ms; }
  .tree-list.anim-in .tree-item:nth-child(5)  { animation-delay: 80ms; }
  .tree-list.anim-in .tree-item:nth-child(n+6){ animation-delay: 90ms; }

  /* blob viewer animation */
  .blob-viewer.anim-in { animation: scaleIn .25s cubic-bezier(.22,1,.36,1) both; }

  /* branch-item stagger */
  .branch-item.anim-in { animation: fadeSlideUp .22s cubic-bezier(.22,1,.36,1) both; }

  /* card stagger */
  .card.anim-in { animation: fadeSlideUp .3s cubic-bezier(.22,1,.36,1) both; }

  /* modal animation */
  .modal.anim-in { animation: scaleIn .2s cubic-bezier(.22,1,.36,1) both; }

  /* reduce-motion */
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation-duration:.01ms!important; transition-duration:.01ms!important; }
  }

  .stats-bar {
    display:flex; align-items:center; gap:clamp(16px, 1.5vw, 32px);
    font-family: var(--mono);
    font-size: clamp(11px, 0.78rem, 15px);
    color: var(--txt3);
  }
  .stat-item { display:inline-flex; align-items:center; gap:6px; }
  .stat-label { color: var(--txt3); }
  .stat-val { color: var(--txt2); font-weight:500; font-variant-numeric: tabular-nums; }
  .stat-sep { color: var(--border2); margin: 0 2px; }
  #s-up { display:inline-block; min-width: 4.5em; text-align:right; }

  /* ── topbar help btn ── */
  .topbar-help {
    background: none; border: none;
    color: var(--txt3); font-family: var(--mono);
    font-size: clamp(12px, 0.85rem, 16px); font-weight: 500;
    cursor: pointer; padding: 0 clamp(4px,.3vw,8px); transition: color .2s; line-height: 1;
  }
  .topbar-help:hover { color: var(--a2); }

  /* ── topbar divider ── */
  .topbar-sep {
    width: 1px;
    height: clamp(12px, .9rem, 18px);
    background: rgba(255,255,255,.08);
    flex-shrink: 0;
  }

  /* ── file icons ── */
  .fi {
    width: clamp(16px, 1.1rem, 22px);
    height: clamp(16px, 1.1rem, 22px);
    flex-shrink: 0;
    display: inline-block;
    vertical-align: middle;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  .fi-folder { color: #3b82f6; }
  .fi-image  { color: #f472b6; }
  .fi-video  { color: #fb923c; }
  .fi-audio  { color: #c084fc; }
  .fi-code   { color: var(--a); }
  .fi-web    { color: #f97316; }
  .fi-data   { color: #fbbf24; }
  .fi-text   { color: var(--txt2); }
  .fi-archive{ color: #a78bfa; }
  .fi-pdf    { color: #ef4444; }
  .fi-file   { color: var(--txt3); }
  .fi-repo   { color: var(--a2); }

  /* ── layout ── */
  .container { width:90%; max-width:2800px; margin:0 auto; padding:clamp(72px, 5vw, 100px) 0 clamp(24px, 2vw, 48px); }

  /* ── section header ── */
  .section-head {
    display:flex; align-items:center; justify-content:space-between;
    margin-bottom:clamp(14px, 1.2vw, 24px);
  }
  .section-title {
    font-family: var(--mono);
    font-size: clamp(11px, 0.8rem, 15px);
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--txt2);
    display:flex; align-items:center; gap:8px;
  }
  .section-title::before {
    content:'';
    display:inline-block;
    width:3px; height:12px;
    border-radius:2px;
    background:var(--a2);
  }

  /* ── card grid ── */
  .card-grid {
    display:grid;
    grid-template-columns: repeat(auto-fill, minmax(clamp(280px, 20vw, 520px), 1fr));
    gap:clamp(10px, 1vw, 24px);
  }

  /* ── card ── */
  .card {
    background: transparent;
    border: 1px solid var(--border);
    border-radius: var(--r2);
    padding: clamp(14px, 1.1vw, 24px) clamp(16px, 1.2vw, 28px);
    display:flex; flex-direction:column; gap:clamp(6px, .5vw, 12px);
    position:relative;
    transition: border-color .2s, background .2s, transform .2s cubic-bezier(.22,1,.36,1);
    overflow:hidden;
    cursor:pointer;
  }
  .card:hover { border-color: var(--border2); background: rgba(255,255,255,.02); transform:translateY(-2px); }
  .card:active { transform:scale(.98); transition-duration:.08s; }

  .card-name {
    font-family: var(--mono);
    font-size: clamp(13px, 0.93rem, 18px);
    font-weight:500;
    color: var(--txt);
    white-space: nowrap;
    overflow:hidden;
    text-overflow:ellipsis;
  }
  .card-name .icon { color:var(--a2); margin-right:6px; transition:transform .2s; display:inline-flex; align-items:center; vertical-align:middle; }
  .card:hover .card-name .icon { animation: iconWiggle .4s ease; }
  .card-meta {
    font-family: var(--mono);
    font-size: clamp(10px, 0.72rem, 14px);
    color: var(--txt2);
    white-space: nowrap;
    overflow:hidden;
    text-overflow:ellipsis;
  }

  /* ── buttons ── */
  .btn {
    display:inline-flex; align-items:center; gap:6px;
    padding: clamp(6px, .5vw, 12px) clamp(12px, 1vw, 22px);
    font-family: var(--mono);
    font-size: clamp(11px, 0.78rem, 15px);
    font-weight:500;
    letter-spacing:.5px;
    border-radius: var(--r);
    border: 1px solid;
    cursor:pointer;
    transition: all .15s;
    white-space:nowrap;
    text-decoration:none;
  }
  .btn-ghost {
    background:transparent;
    border-color: var(--border2);
    color: var(--txt2);
  }
  .btn-ghost:hover { border-color:var(--a2); color:var(--a2); }
  .btn-danger { background:transparent; border-color:transparent; color:var(--txt3); }
  .btn-danger:hover { border-color:var(--danger); color:var(--danger); }
  .icon-btn {
    background:none; border:none;
    font-family: var(--mono);
    font-size: clamp(20px, 1.4rem, 30px);
    color: var(--txt3);
    cursor:pointer;
    padding: clamp(6px,.5vw,12px) clamp(8px,.7vw,14px);
    border-radius: var(--r);
    transition: color .15s, background .15s;
    line-height:1;
  }
  .icon-btn:hover { color: var(--a2); background: rgba(255,255,255,.04); }
  .icon-btn:active { transform:scale(.88); transition-duration:.08s; }
  .icon-btn.danger:hover { color: var(--danger); background: rgba(255,51,85,.06); }
  .btn-danger-fill {
    background:var(--danger); border-color:var(--danger); color:#fff; font-weight:700;
  }
  .btn-danger-fill:hover:not(:disabled) { background:#ff5577; border-color:#ff5577; }
  .btn-danger-fill:disabled { opacity:.25; pointer-events:none; }
  .btn-primary {
    background:var(--a);
    border-color:var(--a);
    color:#000;
    font-weight:700;
  }
  .btn-primary:hover { background:#00ffb3; border-color:#00ffb3; }
  .btn-primary:disabled { opacity:.35; pointer-events:none; }
  .btn-blue {
    background:var(--a2);
    border-color:var(--a2);
    color:#000;
    font-weight:700;
  }
  .btn-blue:hover { background:#38bdf8; border-color:#38bdf8; }
  .btn-sm { padding:clamp(4px,.35vw,8px) clamp(9px,.7vw,16px); font-size:clamp(10px, 0.72rem, 14px); }

  /* ── detail header ── */
  .detail-header {
    display:flex; align-items:center; gap:clamp(12px, 1vw, 20px);
    margin-bottom: clamp(28px, 2.2vw, 48px);
    flex-wrap: wrap;
  }
  .detail-header-top {
    display:contents;
  }
  .detail-info {
    min-width:0;
    flex:1;
    display:flex; align-items:center; gap:clamp(14px, 1.2vw, 24px);
    flex-wrap:wrap;
  }
  .detail-name {
    font-family: var(--mono);
    font-size: clamp(15px, 1.1rem, 22px);
    font-weight: 600;
    color: var(--txt);
  }
  .detail-actions {
    display:flex; align-items:center; gap:clamp(4px,.3vw,8px);
    margin-left:auto;
  }

  /* ── copy box ── */
  .copy-box {
    background:transparent;
    border:1px solid var(--border);
    border-radius:var(--r);
    padding:clamp(8px, .6vw, 14px) clamp(12px, 1vw, 20px);
    font-family:var(--mono); font-size:clamp(12px, 0.85rem, 16px);
    color:var(--a2);
    cursor:pointer;
    transition: border-color .15s;
    word-break:break-all;
  }
  .copy-box:hover { border-color:var(--a2); }
  .copy-box.sm { padding:clamp(5px,.4vw,10px) clamp(10px,.8vw,16px); font-size:clamp(11px, 0.78rem, 15px); display:inline-block; }

  /* ── tabs ── */
  .tab-bar {
    display:flex; gap:clamp(4px, .4vw, 8px);
    margin-bottom: clamp(18px, 1.5vw, 32px);
  }
  .tab {
    padding: clamp(8px, .6vw, 14px) clamp(18px, 1.4vw, 32px);
    font-family: var(--mono);
    font-size: clamp(12px, 0.85rem, 16px);
    font-weight: 500;
    color: var(--txt3);
    background: transparent;
    border: none;
    border-radius: var(--r);
    cursor: pointer;
    transition: all .2s cubic-bezier(.22,1,.36,1);
    letter-spacing: .5px;
    display: inline-flex;
    align-items: center;
    gap: clamp(6px, .5vw, 10px);
  }
  .tab-icon {
    width: clamp(14px, 1rem, 18px);
    height: clamp(14px, 1rem, 18px);
    fill: none;
    stroke: currentColor;
    stroke-width: 1.5;
    stroke-linecap: round;
    stroke-linejoin: round;
    flex-shrink: 0;
  }
  .tab:active { transform:scale(.94); }
  .tab:hover { color: var(--txt2); background: rgba(255,255,255,.03); }
  .tab.active { color: var(--a2); background: rgba(14,165,233,.08); }
  .tab.active[data-tab="branches"] { color: var(--a3); background: rgba(168,85,247,.08); }
  .tab.active[data-tab="upload"] { color: var(--a); background: rgba(0,229,160,.08); }
  .tab.active[data-tab="commits"] { color: #f59e0b; background: rgba(245,158,11,.08); }

  /* ── tree controls ── */
  .tree-controls {
    display:flex; align-items:center; gap:clamp(12px, 1vw, 20px);
    margin-bottom: clamp(14px, 1.2vw, 24px);
    flex-wrap: wrap;
  }
  .select {
    background: transparent;
    border: 1px solid var(--border2);
    border-radius: 999px;
    padding: clamp(5px, .4vw, 10px) clamp(28px, 2vw, 40px) clamp(5px, .4vw, 10px) clamp(12px, .9vw, 18px);
    font-family: var(--mono);
    font-size: clamp(12px, 0.85rem, 16px);
    color: var(--a);
    outline: none;
    cursor: pointer;
    min-width: clamp(120px, 10vw, 200px);
    -webkit-appearance: none;
    -moz-appearance: none;
    appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23666' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right clamp(10px,.7vw,16px) center;
    transition: border-color .2s ease;
  }
  .select:focus { border-color: var(--a); }
  .select option { background: #0a0a0a; color: var(--txt); }
  .select.hidden { display: none; }
  .branch-label {
    font-family: var(--mono);
    font-size: clamp(12px, 0.85rem, 16px);
    color: var(--a2);
  }
  .branch-chip {
    display:inline-flex; align-items:center; gap:5px;
    font-family: var(--mono);
    font-size: clamp(11px, 0.78rem, 15px);
    color: var(--a3);
    background: rgba(168,85,247,.08);
    border: 1px solid rgba(168,85,247,.15);
    border-radius: 999px;
    padding: clamp(3px,.25vw,6px) clamp(10px,.8vw,16px);
    white-space: nowrap;
  }
  .branch-chip::before {
    content:'⎇';
    font-size: clamp(10px, 0.7rem, 14px);
    opacity:.7;
  }

  /* ── breadcrumb ── */
  .breadcrumb {
    display:flex; align-items:center; gap:2px;
    font-family: var(--mono);
    font-size: clamp(12px, 0.85rem, 16px);
    flex-wrap: wrap;
  }
  .crumb {
    color: var(--a2);
    cursor: pointer;
    padding: clamp(2px, .2vw, 6px) clamp(5px, .4vw, 10px);
    border-radius: 3px;
    transition: background .15s;
  }
  .crumb:hover { background: var(--bg3); }
  .crumb.current { color: var(--txt); cursor: default; }
  .crumb.current:hover { background: transparent; }
  .crumb-sep { color: var(--txt3); margin: 0 1px; }
  .path-sep { color: var(--border2); margin: 0 clamp(4px,.3vw,8px); font-size:clamp(10px,.7rem,14px); }

  /* ── tree list ── */
  .tree-list {
    border: none;
    border-radius: 0;
    overflow: hidden;
  }
  .tree-item {
    display: flex;
    align-items: center;
    padding: clamp(10px, .8vw, 18px) clamp(8px, .6vw, 16px);
    border-bottom: 1px solid rgba(255,255,255,.04);
    cursor: pointer;
    transition: background .12s;
    border-radius: var(--r);
    margin-bottom: 1px;
  }
  .tree-item:last-child { border-bottom: none; }
  .tree-item:hover { background: rgba(255,255,255,.03); }
  .tree-icon { width: clamp(26px, 1.8rem, 36px); flex-shrink: 0; display:inline-flex; align-items:center; justify-content:center; transition:transform .2s; }
  .tree-item:hover .tree-icon { animation: iconBounce .35s ease; }
  .tree-name {
    flex: 1;
    font-family: var(--mono);
    font-size: clamp(13px, 0.93rem, 18px);
    color: var(--txt);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .tree-item[data-type="tree"] .tree-name { color: var(--a2); }
  .tree-size {
    font-family: var(--mono);
    font-size: clamp(11px, 0.78rem, 15px);
    color: var(--txt3);
    margin-left: clamp(12px, 1vw, 20px);
    white-space: nowrap;
  }

  /* ── blob viewer ── */
  .blob-viewer {
    border: 1px solid var(--border);
    border-radius: var(--r2);
    overflow: hidden;
  }
  .blob-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: clamp(10px, .8vw, 18px) clamp(14px, 1.1vw, 24px);
    background: transparent;
    border-bottom: 1px solid rgba(255,255,255,.04);
    font-family: var(--mono);
    font-size: clamp(12px, 0.85rem, 16px);
    color: var(--txt);
  }
  .blob-title {
    display: inline-flex; align-items: center; gap: clamp(6px, .5vw, 10px);
    font-weight: 500; min-width: 0;
  }
  .blob-title .fi { flex-shrink: 0; }
  .blob-header-right {
    display: flex; align-items: center; gap: clamp(10px, .8vw, 16px); flex-shrink:0;
  }
  .blob-close {
    background: none; border: 1px solid var(--border2); border-radius: var(--r);
    color: var(--txt3); cursor: pointer; font-family: var(--mono);
    font-size: clamp(12px, 0.85rem, 16px); padding: clamp(4px,.3vw,8px) clamp(10px,.8vw,16px);
    transition: color .15s, border-color .15s, background .15s; line-height:1;
    display:inline-flex; align-items:center; gap:5px;
  }
  .blob-close:hover { color:var(--txt); border-color:var(--txt2); background:rgba(255,255,255,.04); }
  .blob-media {
    display:flex; align-items:center; justify-content:center;
    padding: clamp(20px, 1.5vw, 40px);
    background: var(--bg1); min-height: 200px;
  }
  .blob-media img {
    max-width:100%; max-height:70vh; border-radius:var(--r); object-fit:contain;
  }
  .blob-media video {
    max-width:100%; max-height:70vh; border-radius:var(--r);
  }
  .blob-media audio { width:100%; max-width:500px; }
  .blob-audio {
    padding:clamp(40px,3vw,60px) clamp(20px,1.5vw,40px);
  }
  .blob-code {
    padding: clamp(14px, 1.1vw, 24px);
    font-family: var(--mono);
    font-size: clamp(12px, 0.85rem, 16px);
    line-height: 1.7;
    color: var(--txt);
    background: transparent;
    margin: 0;
    overflow-x: auto;
    max-height: 70vh;
    tab-size: 4;
    -moz-tab-size: 4;
  }
  .blob-binary {
    padding: clamp(40px, 3vw, 60px) clamp(14px, 1.1vw, 24px);
    text-align: center;
    font-family: var(--mono);
    font-size: clamp(12px, 0.85rem, 16px);
    color: var(--txt3);
  }

  /* ── branch list ── */
  .branch-item {
    padding: clamp(12px, 1vw, 20px) clamp(8px, .6vw, 16px);
    border: none;
    border-radius: var(--r);
    margin-bottom: clamp(4px, .3vw, 8px);
    cursor: pointer;
    transition: background .15s;
  }
  .branch-item:hover { background: rgba(255,255,255,.03); }
  .branch-item.default { border-left: 3px solid var(--a2); padding-left: clamp(10px, .8vw, 18px); }
  .branch-name {
    font-family: var(--mono);
    font-size: clamp(13px, 0.93rem, 18px);
    font-weight: 600;
    color: var(--txt);
    margin-bottom: clamp(4px, .3vw, 8px);
  }
  .branch-meta {
    display: flex;
    gap: clamp(12px, 1vw, 20px);
    font-family: var(--mono);
    font-size: clamp(11px, 0.78rem, 15px);
    color: var(--txt3);
    flex-wrap: wrap;
  }
  .branch-hash { color: var(--a3); }
  .branch-subject {
    color: var(--txt2);
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  /* ── commit history ── */
  .commit-controls { display:flex; align-items:center; gap:clamp(10px,.8vw,18px); margin-bottom:clamp(14px,1.1vw,24px); }
  .commit-item {
    border-left: 2px solid rgba(255,255,255,.06);
    padding: clamp(12px,1vw,20px) clamp(12px,1vw,20px);
    margin-left: clamp(6px,.5vw,12px);
    margin-bottom: 2px;
    position: relative;
    transition: background .15s;
  }
  .commit-item:hover { background: rgba(255,255,255,.02); }
  .commit-item::before {
    content:''; position:absolute; left:calc(clamp(-8px,-.6vw,-12px));
    top:clamp(18px,1.3vw,26px); width:clamp(8px,.6vw,12px); height:clamp(8px,.6vw,12px);
    border-radius:50%; background:var(--bg); border:2px solid rgba(255,255,255,.12);
  }
  .commit-item.expanded::before { border-color:var(--a2); background:var(--a2); }
  .commit-head { display:flex; align-items:flex-start; gap:clamp(8px,.6vw,14px); cursor:pointer; }
  .commit-dot { display:none; }
  .commit-info { flex:1; min-width:0; }
  .commit-subject {
    font-family:var(--mono); font-size:clamp(13px,0.9rem,17px); font-weight:600;
    color:var(--txt); margin-bottom:4px; line-height:1.4;
  }
  .commit-meta {
    display:flex; flex-wrap:wrap; gap:clamp(8px,.6vw,16px);
    font-family:var(--mono); font-size:clamp(10px,0.72rem,14px); color:var(--txt3);
  }
  .commit-hash { color:var(--a3); cursor:pointer; }
  .commit-hash:hover { text-decoration:underline; }
  .commit-author { color:var(--txt2); }
  .commit-time { color:var(--txt3); }
  .commit-toggle {
    background:none; border:1px solid rgba(255,255,255,.08); border-radius:var(--r);
    color:var(--txt3); font-family:var(--mono); font-size:clamp(10px,0.72rem,14px);
    padding:clamp(3px,.25vw,6px) clamp(8px,.6vw,14px); cursor:pointer;
    transition:all .2s; white-space:nowrap; flex-shrink:0; align-self:center;
  }
  .commit-toggle:hover { border-color:var(--a2); color:var(--a2); }
  .commit-body {
    margin-top:clamp(10px,.8vw,18px); padding-top:clamp(10px,.8vw,18px);
    border-top:1px solid rgba(255,255,255,.04);
    animation: fadeSlideUp .2s cubic-bezier(.22,1,.36,1) both;
  }
  .commit-stats {
    display:flex; gap:clamp(12px,1vw,24px); margin-bottom:clamp(10px,.8vw,18px);
    font-family:var(--mono); font-size:clamp(10px,0.72rem,14px);
  }
  .commit-stat-files { color:var(--txt2); }
  .commit-stat-add { color:#22c55e; }
  .commit-stat-del { color:#ef4444; }
  .commit-file-list { list-style:none; padding:0; margin:0; }
  .commit-file {
    display:flex; align-items:center; gap:clamp(8px,.6vw,14px);
    padding:clamp(6px,.4vw,10px) clamp(8px,.6vw,14px);
    border-radius:var(--r); font-family:var(--mono);
    font-size:clamp(11px,0.78rem,15px); transition:background .15s;
  }
  .commit-file:hover { background:rgba(255,255,255,.03); }
  .commit-file-status {
    font-size:clamp(9px,0.65rem,12px); font-weight:700;
    padding:2px 6px; border-radius:4px; text-transform:uppercase;
    flex-shrink:0; letter-spacing:.5px;
  }
  .commit-file-status.A { background:rgba(34,197,94,.12); color:#22c55e; }
  .commit-file-status.M { background:rgba(14,165,233,.12); color:#0ea5e9; }
  .commit-file-status.D { background:rgba(239,68,68,.12); color:#ef4444; }
  .commit-file-status.R { background:rgba(168,85,247,.12); color:#a855f7; }
  .commit-file-name { flex:1; color:var(--txt2); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; min-width:0; }
  .commit-file-stats {
    font-size:clamp(10px,0.72rem,13px); color:var(--txt3); white-space:nowrap; flex-shrink:0;
  }
  .commit-file-stats .add { color:#22c55e; }
  .commit-file-stats .del { color:#ef4444; }
  .commit-file-peek {
    background:none; border:1px solid rgba(255,255,255,.06); border-radius:var(--r);
    color:var(--txt3); font-family:var(--mono); font-size:clamp(9px,0.65rem,12px);
    padding:2px 8px; cursor:pointer; transition:all .2s; flex-shrink:0;
  }
  .commit-file-peek:hover { border-color:var(--a2); color:var(--a2); }
  .commit-diff {
    margin-top:6px; border-radius:var(--r); overflow:hidden;
    border:1px solid rgba(255,255,255,.06);
    animation: fadeSlideUp .15s cubic-bezier(.22,1,.36,1) both;
  }
  .diff-line {
    padding:1px clamp(10px,.8vw,18px); font-family:var(--mono);
    font-size:clamp(10px,0.72rem,13px); white-space:pre-wrap; word-break:break-all;
    line-height:1.6;
  }
  .diff-line.add { background:rgba(34,197,94,.08); color:#86efac; }
  .diff-line.del { background:rgba(239,68,68,.08); color:#fca5a5; }
  .diff-line.hunk { color:var(--a3); background:rgba(168,85,247,.06); font-weight:600; }
  .diff-line.ctx { color:var(--txt3); }
  .commit-load-more {
    display:block; width:100%; margin-top:clamp(10px,.8vw,18px);
    background:none; border:1px solid rgba(255,255,255,.06); border-radius:var(--r);
    color:var(--txt3); font-family:var(--mono); font-size:clamp(11px,0.78rem,15px);
    padding:clamp(10px,.8vw,18px); cursor:pointer; transition:all .2s; text-align:center;
  }
  .commit-load-more:hover { border-color:var(--a2); color:var(--a2); }

  /* ── upload form ── */
  .upload-form { max-width: clamp(600px, 45vw, 900px); }
  .form-row { margin-bottom: clamp(14px, 1.1vw, 24px); }
  .form-row label {
    display: block;
    font-family: var(--mono);
    font-size: clamp(11px, 0.78rem, 15px);
    color: var(--txt2);
    margin-bottom: 6px;
    letter-spacing: .5px;
  }

  .input {
    width:100%;
    background: #0a0a0a;
    border: 1px solid rgba(255,255,255,.08);
    border-radius:var(--r);
    padding: clamp(10px, .8vw, 16px) clamp(12px, 1vw, 20px);
    font-family:var(--mono);
    font-size: clamp(13px, 0.93rem, 18px);
    color:var(--txt);
    outline:none;
    transition:border-color .15s;
  }
  .input.error { border-color: var(--danger); }
  .input:focus { border-color:var(--a); }

  .upload-drop {
    border: 1px dashed var(--border2);
    border-radius: var(--r2);
    padding: clamp(32px, 2.5vw, 56px) clamp(20px, 1.8vw, 40px);
    text-align: center;
    cursor: pointer;
    transition: all .2s;
    background: transparent;
    margin-bottom: clamp(14px, 1.1vw, 24px);
    position: relative;
  }
  .upload-drop.drag { border-color: var(--a); background: rgba(0,229,160,.04); }
  .upload-drop input[type=file] { position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%; }
  .drop-icon { font-size:clamp(28px, 2rem, 40px); display:block; margin-bottom:clamp(8px, .6vw, 14px); transition:transform .2s; }
  .upload-drop:hover .drop-icon { animation: iconBounce .5s ease infinite; }
  .drop-title { font-family:var(--mono); font-size:clamp(12px, 0.85rem, 16px); color:var(--txt2); }
  .drop-title span { color:var(--a); }

  .staged-list { margin-bottom: 14px; }
  .staged-item {
    display: flex;
    align-items: center;
    gap: clamp(8px, .6vw, 14px);
    padding: clamp(8px, .6vw, 14px) clamp(12px, 1vw, 20px);
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--r);
    margin-bottom: clamp(6px, .5vw, 10px);
    font-family: var(--mono);
    font-size: clamp(12px, 0.85rem, 16px);
  }
  .staged-item .name { flex: 1; color: var(--txt); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .staged-item .size { color: var(--txt3); font-size: clamp(11px, 0.78rem, 15px); white-space: nowrap; }
  .staged-item .remove {
    background: none; border: none;
    color: var(--txt3); cursor: pointer;
    font-size: 14px; padding: 0 4px;
    transition: color .15s;
  }
  .staged-item .remove:hover { color: var(--danger); }

  /* ── toast ── */
  #toast-wrap {
    position:fixed; bottom:20px; right:20px;
    display:flex; flex-direction:column; gap:8px;
    z-index:999;
  }
  .toast {
    background: var(--bg3);
    border: 1px solid var(--border2);
    border-radius:var(--r);
    padding:clamp(10px, .8vw, 18px) clamp(16px, 1.2vw, 28px);
    font-family:var(--mono);
    font-size:clamp(12px, 0.85rem, 16px);
    max-width:clamp(320px, 24vw, 440px);
    animation: slideIn .2s ease;
    border-left: 3px solid var(--a);
  }
  .toast.err { border-left-color: var(--danger); }
  @keyframes slideIn {
    from { transform:translateX(20px); opacity:0; }
    to   { transform:translateX(0);    opacity:1; }
  }

  /* ── modal ── */
  .modal-bg {
    display:none;
    position:fixed; inset:0; z-index:200;
    background: rgba(0,0,0,.85);
    backdrop-filter:blur(6px);
    align-items:center; justify-content:center;
  }
  .modal-bg.open { display:flex; }
  .modal {
    background: #080808;
    border: 1px solid rgba(255,255,255,.06);
    border-radius: var(--r2);
    padding: clamp(24px, 2vw, 40px);
    width:100%;
    max-width:clamp(420px, 32vw, 600px);
    box-shadow: 0 24px 60px rgba(0,0,0,.9);
  }
  .modal-title {
    font-family:var(--mono); font-size:clamp(12px, 0.85rem, 16px); letter-spacing:2px; text-transform:uppercase;
    color:var(--a); margin-bottom:clamp(16px, 1.2vw, 28px);
  }
  .modal-actions { display:flex; gap:14px; justify-content:flex-end; }

  /* ── help ── */
  .help-body p {
    font-family:var(--mono); font-size:clamp(12px, 0.85rem, 16px); color:var(--txt2);
    margin:clamp(12px, 1vw, 20px) 0 clamp(6px, .5vw, 10px);
  }
  .help-body p:first-child { margin-top:0; }
  .help-body .copy-box { margin-bottom:6px; }

  /* ── empty state ── */
  .empty {
    grid-column:1/-1;
    text-align:center;
    padding:clamp(32px, 2.5vw, 56px);
    font-family:var(--mono); font-size:clamp(12px, 0.85rem, 16px); color:var(--txt3);
  }
  .empty.err { color: var(--danger); }
  .loading {
    text-align:center;
    padding:clamp(32px, 2.5vw, 56px);
    font-family:var(--mono); font-size:clamp(12px, 0.85rem, 16px); color:var(--txt3);
  }
  .hint { color: var(--txt3); font-size: clamp(11px, 0.78rem, 15px); }

  /* ── user profile pill ── */
  .user-pill {
    position:fixed; bottom:20px; left:20px; z-index:90;
    display:flex; align-items:center; gap:10px;
    background:#060606; border:1px solid rgba(255,255,255,.06);
    border-radius:999px; padding:6px 14px 6px 6px;
    cursor:pointer; transition:all .25s ease;
    user-select:none;
  }
  .user-pill:hover { border-color:rgba(0,229,160,.2); background:#0a0a0a; }
  .user-avatar {
    width:32px; height:32px; border-radius:50%;
    background:rgba(0,229,160,.1); border:1px solid rgba(0,229,160,.2);
    overflow:hidden; flex-shrink:0;
  }
  .user-avatar img { width:100%; height:100%; object-fit:cover; display:block; }
  .user-name {
    font-family:var(--mono); font-size:12px; color:var(--txt2);
    max-width:120px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
  }

  .profile-panel {
    position:fixed; bottom:70px; left:20px; z-index:91;
    background:#060606; border:1px solid rgba(255,255,255,.06);
    border-radius:14px; padding:20px; width:280px;
    display:none; animation:profileIn .2s ease;
  }
  .profile-panel.open { display:block; }
  .profile-panel::before {
    content:''; position:absolute; top:0; left:24px; right:24px; height:1px;
    background:linear-gradient(90deg,transparent,rgba(0,229,160,.15),transparent);
  }
  @keyframes profileIn { from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)} }

  .profile-avatar-lg {
    width:56px; height:56px; border-radius:50%; margin:0 auto 14px;
    background:rgba(0,229,160,.08); border:2px solid rgba(0,229,160,.15);
    overflow:hidden;
  }
  .profile-avatar-lg img { width:100%; height:100%; object-fit:cover; display:block; }
  .profile-username {
    text-align:center; font-family:var(--mono); font-size:14px; color:var(--txt);
    font-weight:500; margin-bottom:4px;
  }
  .profile-role {
    text-align:center; font-family:var(--mono); font-size:10px; color:var(--txt2);
    text-transform:uppercase; letter-spacing:1px; margin-bottom:16px;
  }

  .profile-sep { height:1px; background:rgba(255,255,255,.04); margin:12px 0; }

  .profile-field { margin-bottom:12px; }
  .profile-field label {
    display:block; font-family:var(--mono); font-size:10px; color:var(--txt2);
    text-transform:uppercase; letter-spacing:.5px; margin-bottom:4px;
  }
  .profile-field input {
    width:100%; background:rgba(255,255,255,.03); border:1px solid rgba(255,255,255,.06);
    border-radius:8px; padding:8px 10px; font-family:var(--mono); font-size:12px;
    color:var(--txt); outline:none; transition:border-color .2s;
  }
  .profile-field input:focus { border-color:rgba(0,229,160,.25); }

  .profile-btn {
    width:100%; padding:9px; background:transparent; border:1px solid rgba(255,255,255,.06);
    border-radius:8px; font-family:var(--mono); font-size:11px; color:var(--txt2);
    cursor:pointer; transition:all .2s; text-transform:uppercase; letter-spacing:.5px;
  }
  .profile-btn:hover { border-color:rgba(0,229,160,.2); color:var(--a); }
  .profile-btn.danger:hover { border-color:rgba(255,51,85,.2); color:var(--danger); }
  .profile-btn.primary { background:var(--a); color:#000; border-color:var(--a); font-weight:600; }
  .profile-btn.primary:hover { box-shadow:0 0 16px rgba(0,229,160,.2); }

  .profile-actions { display:flex; flex-direction:column; gap:8px; margin-top:4px; }
</style>
</head>
<body>

<div id="topbar">
  <div class="logo" onclick="closeRepo()" title="Back to repositories">
    <div class="logo-dot"></div>
    GITDOCK
  </div>
  <div class="topbar-sep"></div>
  <span class="stat-item"><span class="stat-label">repos</span> <span class="stat-val" id="s-repos">&mdash;</span></span>
  <span class="stat-sep">&middot;</span>
  <span class="stat-item"><span class="stat-label">storage</span> <span class="stat-val" id="s-mb">&mdash;</span></span>
  <span class="stat-sep">&middot;</span>
  <span class="stat-item"><span class="stat-label">uptime</span> <span class="stat-val" id="s-up">&mdash;</span></span>
  <div class="topbar-sep"></div>
  <button class="topbar-help" onclick="openHelp()" title="Git help">?</button>
</div>

<div class="container">

  <!-- ═══ MAIN VIEW ═══ -->
  <div id="main-view">
    <div class="section-head">
      <div class="section-title">Git repositories</div>
      <button class="btn btn-blue btn-sm" onclick="openNewRepo()">+ New repo</button>
    </div>
    <div class="card-grid" id="repo-grid">
      <div class="empty">Loading…</div>
    </div>
  </div>

  <!-- ═══ REPO DETAIL VIEW ═══ -->
  <div id="detail-view" style="display:none">
    <div class="detail-header">
      <button class="icon-btn" onclick="closeRepo()" title="Back">←</button>
      <div class="detail-info">
        <div class="detail-name" id="d-name"></div>
        <div class="copy-box sm" id="d-url" onclick="copyText(this)"></div>
      </div>
      <div class="detail-actions">
        <button class="icon-btn danger" id="d-delete" title="Delete">✕</button>
      </div>
    </div>

    <div class="tab-bar">
      <button class="tab active" data-tab="files" onclick="switchTab('files')"><svg class="tab-icon" viewBox="0 0 24 24"><path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>Files</button>
      <button class="tab" data-tab="branches" onclick="switchTab('branches')"><svg class="tab-icon" viewBox="0 0 24 24"><circle cx="6" cy="6" r="2"/><circle cx="18" cy="18" r="2"/><circle cx="6" cy="18" r="2"/><path d="M6 8v8M18 16V8a4 4 0 00-4-4h-2"/></svg>Branches</button>
      <button class="tab" data-tab="commits" onclick="switchTab('commits')"><svg class="tab-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M1.05 12H7m10 0h5.95M12 1.05V7m0 10v5.95"/></svg>Commits</button>
      <button class="tab" data-tab="upload" onclick="switchTab('upload')"><svg class="tab-icon" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12"/></svg>Upload</button>
    </div>

    <!-- Tab: Files -->
    <div class="tab-panel" id="panel-files">
      <div class="tree-controls">
        <select class="select hidden" id="tree-branch" onchange="switchBranch(this.value)"></select>
        <span class="branch-chip" id="branch-single" style="display:none"></span>
        <span class="path-sep">›</span>
        <div class="breadcrumb" id="breadcrumb"></div>
      </div>
      <div id="tree-view"><div class="loading">Loading…</div></div>
    </div>

    <!-- Tab: Branches -->
    <div class="tab-panel" id="panel-branches" style="display:none">
      <div id="branch-list"><div class="loading">Loading…</div></div>
    </div>

    <!-- Tab: Commits -->
    <div class="tab-panel" id="panel-commits" style="display:none">
      <div class="commit-controls">
        <select class="select hidden" id="commit-branch" onchange="loadCommits(this.value)"></select>
        <span class="branch-chip" id="commit-branch-single" style="display:none"></span>
      </div>
      <div id="commit-list"><div class="loading">Loading…</div></div>
    </div>

    <!-- Tab: Upload & Commit -->
    <div class="tab-panel" id="panel-upload" style="display:none">
      <div class="upload-form">
        <div class="form-row">
          <label>Branch</label>
          <input class="input" id="up-branch" list="up-branches" placeholder="main" autocomplete="off">
          <datalist id="up-branches"></datalist>
        </div>
        <div class="form-row">
          <label>Commit message</label>
          <input class="input" id="up-msg" placeholder="Add files via web upload" autocomplete="off">
        </div>
        <div class="form-row">
          <label>Path prefix <span class="hint">(optional, e.g. src/assets/)</span></label>
          <input class="input" id="up-prefix" placeholder="" autocomplete="off">
        </div>
        <div id="up-drop" class="upload-drop">
          <input type="file" id="up-input" multiple>
          <span class="drop-icon">⬆</span>
          <div class="drop-title">Drop files or <span>click to browse</span></div>
        </div>
        <div id="up-staged" class="staged-list"></div>
        <button class="btn btn-primary" id="up-commit" onclick="commitFiles()" disabled>Commit 0 files</button>
      </div>
    </div>
  </div>

</div>



<!-- ── MODAL: new repo ── -->
<div class="modal-bg" id="repo-modal">
  <div class="modal">
    <div class="modal-title">// New Repository</div>
    <input class="input" id="repo-name-input" placeholder="my-project  (no spaces)" autocomplete="off" spellcheck="false" style="margin-bottom:clamp(14px,1.1vw,24px)">
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeNewRepo()">Cancel</button>
      <button class="btn btn-blue" onclick="createRepo()">Create</button>
    </div>
  </div>
</div>

<!-- ── MODAL: help ── -->
<div class="modal-bg" id="help-modal">
  <div class="modal" style="max-width:clamp(520px, 38vw, 720px)">
    <div class="modal-title">// Git Quick Reference</div>
    <div class="help-body">
      <p><b>Push to a new repo:</b></p>
      <div class="copy-box" onclick="copyText(this)">git remote add origin http://&lt;HOST&gt;/git/myrepo.git</div>
      <div class="copy-box" onclick="copyText(this)">git push -u origin main</div>
      <p><b>Clone a repo:</b></p>
      <div class="copy-box" onclick="copyText(this)">git clone http://&lt;HOST&gt;/git/myrepo.git</div>
      <p><b>Pull latest:</b></p>
      <div class="copy-box" onclick="copyText(this)">git pull origin main</div>
      <p class="hint" style="margin-top:14px">
        Repos are auto-created on first push. Replace &lt;HOST&gt; with your server address and port.
      </p>
    </div>
    <div class="modal-actions" style="margin-top:16px;">
      <button class="btn btn-ghost" onclick="closeHelp()">Close</button>
    </div>
  </div>
</div>

<!-- ── MODAL: delete repo ── -->
<div class="modal-bg" id="delete-modal">
  <div class="modal">
    <div class="modal-title" style="color:var(--danger)">// Delete Repository</div>
    <p style="font-family:var(--mono);font-size:clamp(12px,0.85rem,16px);color:var(--txt2);margin-bottom:clamp(14px,1.1vw,24px);line-height:1.6;">
      This will <strong style="color:var(--danger)">permanently delete</strong> the repository and all its history. This action cannot be undone.
    </p>
    <label style="display:block;font-family:var(--mono);font-size:clamp(11px,0.78rem,15px);color:var(--txt2);margin-bottom:6px;">
      Type <strong id="del-confirm-name" style="color:var(--txt)"></strong> to confirm
    </label>
    <input class="input" id="del-name-input" placeholder="" autocomplete="off" spellcheck="false" style="margin-bottom:clamp(14px,1.1vw,24px);">
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeDeleteModal()">Cancel</button>
      <button class="btn btn-danger-fill" id="del-confirm-btn" disabled onclick="confirmDelete()">Delete</button>
    </div>
  </div>
</div>

<!-- ═══ USER PROFILE ═══ -->
<div class="user-pill" id="user-pill" onclick="toggleProfile()">
  <div class="user-avatar" id="user-avatar-sm"><img id="user-avatar-img-sm" src="" alt=""></div>
  <span class="user-name" id="user-pill-name">...</span>
</div>

<div class="profile-panel" id="profile-panel">
  <div class="profile-avatar-lg" id="user-avatar-lg"><img id="user-avatar-img-lg" src="" alt=""></div>
  <div class="profile-username" id="profile-username"></div>
  <div class="profile-role">administrator</div>
  <div class="profile-sep"></div>
  <div class="profile-field">
    <label>Display Name</label>
    <input id="prof-name" type="text" autocomplete="off" placeholder="Your name">
  </div>
  <div class="profile-sep"></div>
  <div class="profile-field">
    <label>Current Password</label>
    <input id="prof-cur-pw" type="password" autocomplete="off" placeholder="\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022">
  </div>
  <div class="profile-field">
    <label>New Password</label>
    <input id="prof-new-pw" type="password" autocomplete="off" placeholder="\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022">
  </div>
  <div class="profile-actions">
    <button class="profile-btn primary" onclick="saveProfile()">Save changes</button>
    <button class="profile-btn danger" onclick="doLogout()">Sign out</button>
  </div>
</div>

<div id="toast-wrap"></div>

<script>
var HOST = location.origin;
var currentRepo = null;
var currentRef  = 'HEAD';
var currentPath = '';
var viewingBlob = false;
var branchData  = { branches: [], head: null };
var staged      = [];

// ── utils ──────────────────────────────────────────────────────────────────
function toast(msg, err) {
  var t = document.createElement('div');
  t.className = 'toast' + (err ? ' err' : '');
  t.textContent = msg;
  document.getElementById('toast-wrap').appendChild(t);
  setTimeout(function() { t.remove(); }, 3500);
}

function api(url, opt) {
  return fetch(url, opt || {}).then(function(r) {
    if (!r.ok) return r.json().catch(function() { return {}; }).then(function(e) { throw new Error(e.error || r.statusText); });
    return r.json();
  });
}

function copyText(el) {
  navigator.clipboard.writeText(el.textContent).then(function() { toast('Copied!'); });
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function fmtSize(b) {
  if (b == null) return '';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}

// ── stats ──────────────────────────────────────────────────────────────────
var serverUptime = 0;
var uptimeTimer = null;

function fmtUptime(s) {
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s/60) + 'm ' + (s%60) + 's';
  var h = Math.floor(s/3600);
  var m = Math.floor((s%3600)/60);
  return h + 'h ' + m + 'm';
}

function loadInfo() {
  api('/api/info').then(function(i) {
    document.getElementById('s-repos').textContent = i.repos;
    document.getElementById('s-mb').textContent   = i.storageMB + ' MB';
    serverUptime = i.uptime;
    document.getElementById('s-up').textContent = fmtUptime(serverUptime);
  }).catch(function() {});
}
setInterval(loadInfo, 30000);

// tick uptime every second locally
uptimeTimer = setInterval(function() {
  if (serverUptime > 0) {
    serverUptime++;
    document.getElementById('s-up').textContent = fmtUptime(serverUptime);
  }
}, 1000);

// ── file icons ────────────────────────────────────────────────────────────────
function getFileIcon(name, type) {
  var s = '<svg class="fi ';
  var a = '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">';
  if (type === 'tree') return s+'fi-folder'+a+'<path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>';
  var ext = (name.match(/\\.([^.]+)$/) || [])[1];
  ext = ext ? ext.toLowerCase() : '';
  if (/^(png|jpe?g|gif|webp|svg|bmp|ico|avif|tiff?)$/.test(ext))
    return s+'fi-image'+a+'<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>';
  if (/^(mp4|webm|mov|avi|mkv|flv|wmv)$/.test(ext))
    return s+'fi-video'+a+'<rect x="2" y="4" width="15" height="16" rx="2"/><path d="M17 8l5-3v14l-5-3"/></svg>';
  if (/^(mp3|wav|ogg|flac|aac|m4a|wma)$/.test(ext))
    return s+'fi-audio'+a+'<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>';
  if (/^(js|ts|jsx|tsx|py|rb|go|rs|java|c|cpp|h|hpp|cs|swift|kt|dart|lua|sh|bash|pl|php|r)$/.test(ext))
    return s+'fi-code'+a+'<path d="M16 18l6-6-6-6M8 6l-6 6 6 6"/></svg>';
  if (/^(html?|css|scss|sass|less|vue|svelte)$/.test(ext))
    return s+'fi-web'+a+'<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>';
  if (/^(json|xml|ya?ml|toml|csv|tsv|sql|graphql)$/.test(ext))
    return s+'fi-data'+a+'<path d="M8 3H6a2 2 0 00-2 2v4a2 2 0 01-2 2 2 2 0 012 2v4a2 2 0 002 2h2M16 3h2a2 2 0 012 2v4a2 2 0 002 2 2 2 0 00-2 2v4a2 2 0 01-2 2h-2"/></svg>';
  if (/^(md|mdx|txt|text|log|rst)$/.test(ext))
    return s+'fi-text'+a+'<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8M8 17h5"/></svg>';
  if (/^(zip|tar|gz|bz2|xz|7z|rar|tgz|zst)$/.test(ext))
    return s+'fi-archive'+a+'<path d="M21 8v13H3V8"/><path d="M1 3h22v5H1z"/><path d="M10 12h4"/></svg>';
  if (ext === 'pdf')
    return s+'fi-pdf'+a+'<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/></svg>';
  return s+'fi-file'+a+'<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/></svg>';
}

function closeFile() {
  viewingBlob = false;
  var parts = currentPath.split('/');
  parts.pop();
  currentPath = parts.join('/');
  loadTree();
}

// ── repo list ──────────────────────────────────────────────────────────────
function loadRepos() {
  var grid = document.getElementById('repo-grid');
  api('/api/repos').then(function(repos) {
    if (!repos.length) { grid.innerHTML = '<div class="empty">No repos yet — create one or just git push</div>'; return; }
    grid.innerHTML = repos.map(function(r, idx) {
      return '<div class=\"card anim-in\" style=\"animation-delay:' + (idx * 50) + 'ms\" data-repo=\"' + esc(r.name) + '\">' +
        '<div class="card-name"><span class="icon"><svg class="fi fi-repo" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg></span>' + esc(r.name) + '</div>' +
        '<div class="card-meta">' + esc(r.lastCommit || 'empty repo') + '</div>' +
        '<div class="card-meta" style="color:var(--txt3)">' + esc(r.size) + '</div>' +
      '</div>';
    }).join('');
  }).catch(function() {
    grid.innerHTML = '<div class="empty err">Error loading repos</div>';
  });
}

document.getElementById('repo-grid').addEventListener('click', function(e) {
  var card = e.target.closest('.card[data-repo]');
  if (card) openRepo(card.dataset.repo);
});

// ── open / close repo detail ───────────────────────────────────────────────
function openRepo(name) {
  currentRepo = name;
  currentRef  = 'HEAD';
  currentPath = '';
  viewingBlob = false;
  staged = [];
  document.getElementById('d-name').textContent = name;
  document.getElementById('d-url').textContent  = HOST + '/git/' + name;
  document.getElementById('d-delete').onclick   = function() { deleteRepo(name); };
  document.getElementById('main-view').style.display   = 'none';
  var detail = document.getElementById('detail-view');
  detail.style.display = '';
  detail.classList.remove('anim-in');
  void detail.offsetWidth;
  detail.classList.add('anim-in');
  switchTab('files');
  loadBranches().then(function() { loadTree(); });
}

function closeRepo() {
  if (!currentRepo) return;
  currentRepo = null;
  staged = [];
  var main = document.getElementById('main-view');
  document.getElementById('detail-view').style.display = 'none';
  main.style.display   = '';
  main.classList.remove('anim-in');
  void main.offsetWidth;
  main.classList.add('anim-in');
  loadRepos();
  loadInfo();
}

// ── tabs ───────────────────────────────────────────────────────────────────
function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(function(t) {
    t.classList.toggle('active', t.dataset.tab === tab);
  });
  ['files','branches','commits','upload'].forEach(function(p) {
    var panel = document.getElementById('panel-' + p);
    if (p === tab) {
      panel.style.display = '';
      panel.classList.remove('anim-in');
      void panel.offsetWidth;
      panel.classList.add('anim-in');
    } else {
      panel.style.display = 'none';
      panel.classList.remove('anim-in');
    }
  });
  if (tab === 'branches') loadBranches();
  if (tab === 'commits') initCommits();
  if (tab === 'upload') updateUploadBranch();
}

// ── branches ───────────────────────────────────────────────────────────────
function loadBranches() {
  if (!currentRepo) return Promise.resolve();
  return api('/api/repos/' + encodeURIComponent(currentRepo) + '/branches').then(function(data) {
    branchData = data;
    if (data.head && currentRef === 'HEAD') currentRef = data.head;

    // file-tab branch select
    var sel = document.getElementById('tree-branch');
    if (data.branches.length > 1) {
      sel.classList.remove('hidden');
      sel.innerHTML = data.branches.map(function(b) {
        return '<option value="' + esc(b.name) + '"' + (b.name === currentRef ? ' selected' : '') + '>' + esc(b.name) + '</option>';
      }).join('');
      document.getElementById('branch-single').style.display = 'none';
    } else if (data.branches.length === 1) {
      sel.classList.add('hidden');
      document.getElementById('branch-single').style.display = '';
      document.getElementById('branch-single').textContent = data.branches[0].name;
    } else {
      sel.classList.add('hidden');
      document.getElementById('branch-single').style.display = '';
      document.getElementById('branch-single').textContent = 'no branches';
    }

    // branch-list tab
    var list = document.getElementById('branch-list');
    if (!data.branches.length) {
      list.innerHTML = '<div class="empty">No branches yet — push some commits first</div>';
      return;
    }
    list.innerHTML = data.branches.map(function(b) {
      return '<div class="branch-item anim-in' + (b.name === data.head ? ' default' : '') + '" data-branch="' + esc(b.name) + '">' +
        '<div class="branch-name">' + (b.name === data.head ? '\u25CF ' : '') + esc(b.name) + '</div>' +
        '<div class="branch-meta">' +
          '<span class="branch-hash">' + esc(b.hash) + '</span>' +
          '<span>' + esc(b.date) + '</span>' +
          '<span class="branch-subject">' + esc(b.subject) + '</span>' +
        '</div>' +
      '</div>';
    }).join('');
  }).catch(function() {
    document.getElementById('branch-list').innerHTML = '<div class="empty err">Error loading branches</div>';
  });
}

document.getElementById('branch-list').addEventListener('click', function(e) {
  var item = e.target.closest('.branch-item[data-branch]');
  if (item) {
    switchBranch(item.dataset.branch);
    switchTab('files');
  }
});

// ── commit history ─────────────────────────────────────────────────────────
var commitSkip = 0;
var commitBranch = '';
var expandedCommits = {};

function initCommits() {
  var sel = document.getElementById('commit-branch');
  var chip = document.getElementById('commit-branch-single');
  if (branchData.branches.length > 1) {
    sel.classList.remove('hidden');
    sel.innerHTML = branchData.branches.map(function(b) {
      return '<option value="' + esc(b.name) + '"' + (b.name === currentRef ? ' selected' : '') + '>' + esc(b.name) + '</option>';
    }).join('');
    chip.style.display = 'none';
  } else if (branchData.branches.length === 1) {
    sel.classList.add('hidden');
    chip.style.display = '';
    chip.textContent = branchData.branches[0].name;
  } else {
    sel.classList.add('hidden');
    chip.style.display = '';
    chip.textContent = 'no branches';
  }
  commitBranch = sel.value || currentRef || 'HEAD';
  commitSkip = 0;
  expandedCommits = {};
  loadCommits(commitBranch);
}

function loadCommits(branch, append) {
  if (!currentRepo) return;
  if (!append) {
    commitBranch = branch || commitBranch;
    commitSkip = 0;
    expandedCommits = {};
  }
  var url = '/api/repos/' + encodeURIComponent(currentRepo) + '/log?ref=' + encodeURIComponent(commitBranch) + '&limit=30&skip=' + commitSkip;
  var list = document.getElementById('commit-list');
  if (!append) list.innerHTML = '<div class="loading">Loading\u2026</div>';

  api(url).then(function(data) {
    if (!append) list.innerHTML = '';
    if (!data.commits.length && !append) {
      list.innerHTML = '<div class="empty">No commits on this branch</div>';
      return;
    }
    var html = data.commits.map(function(c, idx) {
      var d = new Date(c.timestamp);
      var timeStr = fmtCommitDate(d);
      return '<div class="commit-item anim-in" style="animation-delay:' + ((append ? 0 : idx) * 30) + 'ms" data-hash="' + esc(c.hash) + '">' +
        '<div class="commit-head" onclick="toggleCommit(this)">' +
          '<div class="commit-info">' +
            '<div class="commit-subject">' + esc(c.subject) + '</div>' +
            '<div class="commit-meta">' +
              '<span class="commit-hash" onclick="event.stopPropagation();copyHash(this)" title="Copy full hash">' + esc(c.shortHash) + '</span>' +
              '<span class="commit-author">' + esc(c.author) + '</span>' +
              '<span class="commit-time">' + esc(timeStr) + '</span>' +
            '</div>' +
          '</div>' +
          '<button class="commit-toggle" onclick="event.stopPropagation();toggleCommit(this.parentNode)">Files</button>' +
        '</div>' +
        '<div class="commit-body" id="cb-' + esc(c.hash) + '" style="display:none"></div>' +
      '</div>';
    }).join('');

    if (append) {
      // remove old load-more button
      var old = list.querySelector('.commit-load-more');
      if (old) old.remove();
    }
    list.insertAdjacentHTML('beforeend', html);
    commitSkip += data.commits.length;

    if (data.commits.length === 30) {
      list.insertAdjacentHTML('beforeend', '<button class="commit-load-more" onclick="loadCommits(null, true)">Load more commits\u2026</button>');
    }
  }).catch(function() {
    if (!append) list.innerHTML = '<div class="empty err">Error loading commits</div>';
  });
}

function fmtCommitDate(d) {
  var now = Date.now();
  var diff = now - d.getTime();
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return Math.floor(diff/60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff/3600000) + 'h ago';
  if (diff < 604800000) return Math.floor(diff/86400000) + 'd ago';
  var mm = String(d.getMonth()+1).padStart(2,'0');
  var dd = String(d.getDate()).padStart(2,'0');
  return d.getFullYear() + '-' + mm + '-' + dd;
}

function copyHash(el) {
  var hash = el.closest('.commit-item').dataset.hash;
  navigator.clipboard.writeText(hash).then(function() { toast('Hash copied'); });
}

function toggleCommit(head) {
  var item = head.closest('.commit-item');
  var hash = item.dataset.hash;
  var body = document.getElementById('cb-' + hash);
  if (item.classList.contains('expanded')) {
    item.classList.remove('expanded');
    body.style.display = 'none';
    return;
  }
  item.classList.add('expanded');
  body.style.display = '';
  if (expandedCommits[hash]) return; // already loaded
  body.innerHTML = '<div class="loading" style="padding:8px 0">Loading\u2026</div>';
  expandedCommits[hash] = true;

  api('/api/repos/' + encodeURIComponent(currentRepo) + '/commit/' + hash).then(function(c) {
    var statusLabel = { A:'Added', M:'Modified', D:'Deleted', R:'Renamed', C:'Copied' };
    var html = '<div class="commit-stats">' +
      '<span class="commit-stat-files">' + c.totalFiles + ' file' + (c.totalFiles !== 1 ? 's' : '') + '</span>' +
      '<span class="commit-stat-add">+' + c.totalAdditions + '</span>' +
      '<span class="commit-stat-del">\u2212' + c.totalDeletions + '</span>' +
    '</div>';
    html += '<ul class="commit-file-list">';
    c.files.forEach(function(f) {
      var sl = statusLabel[f.status] || f.status;
      html += '<li class="commit-file">' +
        '<span class="commit-file-status ' + esc(f.status) + '">' + esc(sl) + '</span>' +
        '<span class="commit-file-name" title="' + esc(f.file) + '">' + esc(f.file) + (f.oldFile ? ' <span style="color:var(--txt3)">\u2190 ' + esc(f.oldFile) + '</span>' : '') + '</span>' +
        '<span class="commit-file-stats">' +
          (f.additions ? '<span class="add">+' + f.additions + '</span> ' : '') +
          (f.deletions ? '<span class="del">\u2212' + f.deletions + '</span>' : '') +
        '</span>' +
        (f.status !== 'D' ? '<button class="commit-file-peek" onclick="peekDiff(this,\\'' + esc(hash) + '\\',\\'' + esc(f.file).replace(/'/g, "\\\\'") + '\\')">Peek</button>' : '') +
      '</li>';
    });
    html += '</ul>';
    if (c.body) {
      html += '<div style="margin-top:10px;padding:8px 12px;background:rgba(255,255,255,.02);border-radius:var(--r);font-family:var(--mono);font-size:clamp(10px,0.72rem,14px);color:var(--txt3);white-space:pre-wrap;">' + esc(c.body) + '</div>';
    }
    body.innerHTML = html;
  }).catch(function() {
    body.innerHTML = '<div class="empty err" style="padding:8px 0">Error loading commit details</div>';
    expandedCommits[hash] = false;
  });
}

function peekDiff(btn, hash, file) {
  var li = btn.closest('.commit-file');
  var existing = li.querySelector('.commit-diff');
  if (existing) { existing.remove(); btn.textContent = 'Peek'; return; }
  btn.textContent = 'Close';
  li.insertAdjacentHTML('beforeend', '<div class="commit-diff"><div class="loading" style="padding:6px 10px">Loading\u2026</div></div>');

  api('/api/repos/' + encodeURIComponent(currentRepo) + '/diff/' + hash + '?file=' + encodeURIComponent(file)).then(function(data) {
    var diffEl = li.querySelector('.commit-diff');
    if (!diffEl) return;
    var lines = data.diff.split('\\n');
    var html = '';
    var inHunk = false;
    lines.forEach(function(line) {
      if (line.startsWith('@@')) {
        inHunk = true;
        html += '<div class="diff-line hunk">' + esc(line) + '</div>';
      } else if (line.startsWith('diff ') || line.startsWith('index ') || line.startsWith('---') || line.startsWith('+++') || line.startsWith('new ') || line.startsWith('old ')) {
        // skip diff headers
      } else if (inHunk && line.startsWith('+')) {
        html += '<div class="diff-line add">' + esc(line) + '</div>';
      } else if (inHunk && line.startsWith('-')) {
        html += '<div class="diff-line del">' + esc(line) + '</div>';
      } else if (inHunk) {
        html += '<div class="diff-line ctx">' + esc(line) + '</div>';
      }
    });
    if (!html) html = '<div class="diff-line ctx">(no diff available)</div>';
    diffEl.innerHTML = html;
  }).catch(function() {
    var diffEl = li.querySelector('.commit-diff');
    if (diffEl) diffEl.innerHTML = '<div class="diff-line ctx">(error loading diff)</div>';
  });
}

function switchBranch(name) {
  currentRef  = name;
  currentPath = '';
  viewingBlob = false;
  document.getElementById('tree-branch').value = name;
  loadTree();
}

function updateUploadBranch() {
  var dl = document.getElementById('up-branches');
  dl.innerHTML = branchData.branches.map(function(b) {
    return '<option value="' + esc(b.name) + '">';
  }).join('');
  var input = document.getElementById('up-branch');
  if (!input.value) input.value = branchData.head || 'main';
  updateStagedUI();
}

// ── file tree ──────────────────────────────────────────────────────────────
function loadTree() {
  if (!currentRepo) return;
  updateBreadcrumb();
  var view = document.getElementById('tree-view');
  view.innerHTML = '<div class="loading">Loading\u2026</div>';
  var qs = 'ref=' + encodeURIComponent(currentRef) + '&path=' + encodeURIComponent(currentPath);
  api('/api/repos/' + encodeURIComponent(currentRepo) + '/tree?' + qs).then(function(items) {
    if (!items.length) {
      view.innerHTML = '<div class="empty">Empty — no files on this branch</div>';
      return;
    }
    var html = '<div class="tree-list anim-in">';
    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      html += '<div class="tree-item anim-in" data-type="' + it.type + '" data-name="' + esc(it.name) + '">' +
        '<span class="tree-icon">' + getFileIcon(it.name, it.type) + '</span>' +
        '<span class="tree-name">' + esc(it.name) + '</span>' +
        '<span class="tree-size">' + (it.type === 'blob' ? fmtSize(it.size) : '') + '</span>' +
      '</div>';
    }
    html += '</div>';
    view.innerHTML = html;
  }).catch(function() {
    view.innerHTML = '<div class="empty">Empty — no files on this branch</div>';
  });
}

document.getElementById('tree-view').addEventListener('click', function(e) {
  var item = e.target.closest('.tree-item');
  if (!item) return;
  var name = item.dataset.name;
  var type = item.dataset.type;
  var fullPath = currentPath ? currentPath + '/' + name : name;
  if (type === 'tree') navigateTo(fullPath);
  else viewFile(fullPath);
});

function navigateTo(dir) {
  currentPath = dir;
  viewingBlob = false;
  loadTree();
}

function viewFile(filePath) {
  var view = document.getElementById('tree-view');
  view.innerHTML = '<div class="loading">Loading\u2026</div>';
  var qs = 'ref=' + encodeURIComponent(currentRef) + '&path=' + encodeURIComponent(filePath);
  api('/api/repos/' + encodeURIComponent(currentRepo) + '/blob?' + qs).then(function(data) {
    viewingBlob = true;
    currentPath = filePath;
    updateBreadcrumb();
    var fname = filePath.split('/').pop();
    var ext = (fname.match(/\\.([^.]+)$/) || [])[1];
    ext = ext ? ext.toLowerCase() : '';
    var icon = getFileIcon(fname, 'blob');
    var rawUrl = '/api/repos/' + encodeURIComponent(currentRepo) + '/raw?ref=' + encodeURIComponent(currentRef) + '&path=' + encodeURIComponent(filePath);
    var closeBtn = '<button class="blob-close" onclick="closeFile()" title="Close file">\u2715 Close</button>';
    var hdr = function(extra) { return '<div class="blob-header"><span class="blob-title">' + icon + ' ' + esc(fname) + '</span><span class="blob-header-right">' + (extra||'') + closeBtn + '</span></div>'; };

    if (/^(png|jpe?g|gif|webp|svg|bmp|ico|avif|tiff?)$/.test(ext)) {
      view.innerHTML = '<div class="blob-viewer anim-in">' + hdr('<span class="hint">Image' + (data.size ? ' \u00B7 ' + fmtSize(data.size) : '') + '</span>') +
        '<div class="blob-media"><img src="' + rawUrl + '" alt="' + esc(fname) + '"></div></div>';
    } else if (/^(mp4|webm|mov)$/.test(ext)) {
      view.innerHTML = '<div class="blob-viewer anim-in">' + hdr('<span class="hint">Video' + (data.size ? ' \u00B7 ' + fmtSize(data.size) : '') + '</span>') +
        '<div class="blob-media"><video controls src="' + rawUrl + '"></video></div></div>';
    } else if (/^(mp3|wav|ogg|flac|aac|m4a)$/.test(ext)) {
      view.innerHTML = '<div class="blob-viewer anim-in">' + hdr('<span class="hint">Audio' + (data.size ? ' \u00B7 ' + fmtSize(data.size) : '') + '</span>') +
        '<div class="blob-media blob-audio"><audio controls src="' + rawUrl + '"></audio></div></div>';
    } else if (data.binary) {
      view.innerHTML = '<div class="blob-viewer anim-in">' +
        hdr('<span class="hint">Binary' + (data.size ? ' \u00B7 ' + fmtSize(data.size) : '') + '</span>') +
        '<div class="blob-binary">Binary file \u2014 cannot display</div></div>';
    } else {
      var lines = data.content.split('\\n').length;
      view.innerHTML = '<div class="blob-viewer anim-in">' +
        hdr('<span class="hint">' + lines + ' lines</span>') +
        '<pre class="blob-code">' + esc(data.content) + '</pre></div>';
    }
  }).catch(function() {
    view.innerHTML = '<div class="empty err">Could not load file</div>';
  });
}

function updateBreadcrumb() {
  var bc = document.getElementById('breadcrumb');
  var parts = currentPath ? currentPath.split('/') : [];
  var html = '<span class="crumb" data-path="">root</span>';
  var acc = '';
  for (var i = 0; i < parts.length; i++) {
    acc += (i > 0 ? '/' : '') + parts[i];
    html += ' <span class="crumb-sep">/</span> ';
    if (i === parts.length - 1 && viewingBlob) {
      html += '<span class="crumb current">' + esc(parts[i]) + '</span>';
    } else {
      html += '<span class="crumb" data-path="' + esc(acc) + '">' + esc(parts[i]) + '</span>';
    }
  }
  bc.innerHTML = html;
}

document.getElementById('breadcrumb').addEventListener('click', function(e) {
  var crumb = e.target.closest('.crumb[data-path]');
  if (crumb) navigateTo(crumb.dataset.path);
});

// ── upload / commit ────────────────────────────────────────────────────────
var dropEl = document.getElementById('up-drop');
var fileIn = document.getElementById('up-input');

dropEl.addEventListener('dragover', function(e) { e.preventDefault(); dropEl.classList.add('drag'); });
dropEl.addEventListener('dragleave', function() { dropEl.classList.remove('drag'); });
dropEl.addEventListener('drop', function(e) {
  e.preventDefault(); dropEl.classList.remove('drag');
  addStagedFiles(Array.from(e.dataTransfer.files));
});
fileIn.addEventListener('change', function() {
  addStagedFiles(Array.from(fileIn.files));
  fileIn.value = '';
});

function addStagedFiles(files) {
  for (var i = 0; i < files.length; i++) staged.push(files[i]);
  updateStagedUI();
}

function removeStagedFile(idx) {
  staged.splice(idx, 1);
  updateStagedUI();
}

function updateStagedUI() {
  var el  = document.getElementById('up-staged');
  var btn = document.getElementById('up-commit');
  if (!staged.length) {
    el.innerHTML = '';
    btn.disabled = true;
    btn.textContent = 'Commit 0 files';
    return;
  }
  btn.disabled = false;
  btn.textContent = 'Commit ' + staged.length + ' file' + (staged.length > 1 ? 's' : '');
  var html = '';
  for (var i = 0; i < staged.length; i++) {
    html += '<div class="staged-item">' +
      '<span class="name">' + esc(staged[i].name) + '</span>' +
      '<span class="size">' + fmtSize(staged[i].size) + '</span>' +
      '<button class="remove" data-idx="' + i + '">\u2715</button>' +
    '</div>';
  }
  el.innerHTML = html;
}

document.getElementById('up-staged').addEventListener('click', function(e) {
  var btn = e.target.closest('.remove[data-idx]');
  if (btn) removeStagedFile(parseInt(btn.dataset.idx));
});

function commitFiles() {
  if (!staged.length || !currentRepo) return;
  var branch  = document.getElementById('up-branch').value.trim() || 'main';
  var message = document.getElementById('up-msg').value.trim() || 'Add files via web upload';
  var prefix  = document.getElementById('up-prefix').value.trim();
  var btn     = document.getElementById('up-commit');
  btn.disabled = true;
  btn.textContent = 'Committing\u2026';

  var fd = new FormData();
  fd.append('branch', branch);
  fd.append('message', message);
  if (prefix) fd.append('prefix', prefix);
  for (var i = 0; i < staged.length; i++) fd.append('files', staged[i]);

  api('/api/repos/' + encodeURIComponent(currentRepo) + '/commit', { method: 'POST', body: fd }).then(function() {
    toast('Committed ' + staged.length + ' file' + (staged.length > 1 ? 's' : '') + ' to ' + branch);
    staged = [];
    updateStagedUI();
    document.getElementById('up-msg').value = '';
    loadBranches();
    if (currentRef === branch) loadTree();
  }).catch(function(err) {
    toast('Commit failed: ' + err.message, true);
    btn.disabled = false;
    btn.textContent = 'Commit ' + staged.length + ' file' + (staged.length > 1 ? 's' : '');
  });
}

// ── new repo modal ─────────────────────────────────────────────────────────
function openNewRepo() {
  var modal = document.getElementById('repo-modal');
  modal.classList.add('open');
  var inner = modal.querySelector('.modal');
  inner.classList.remove('anim-in');
  void inner.offsetWidth;
  inner.classList.add('anim-in');
  document.getElementById('repo-name-input').focus();
}
function closeNewRepo() {
  document.getElementById('repo-modal').classList.remove('open');
  document.getElementById('repo-name-input').value = '';
}
function createRepo() {
  var inp = document.getElementById('repo-name-input');
  var name = inp.value.trim();
  if (!name) { inp.classList.add('error'); return; }
  inp.classList.remove('error');
  api('/api/repos', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: name })
  }).then(function() {
    toast('Repo created: ' + name + '.git');
    closeNewRepo(); loadRepos(); loadInfo();
  }).catch(function(err) { toast('Error: ' + err.message, true); });
}
document.getElementById('repo-name-input').addEventListener('keydown', function(e) {
  this.classList.remove('error');
  if (e.key === 'Enter')  createRepo();
  if (e.key === 'Escape') closeNewRepo();
});

// ── delete repo ────────────────────────────────────────────────────────────
var deleteTarget = null;

function deleteRepo(name) {
  openDeleteModal(name);
}

function openDeleteModal(name) {
  deleteTarget = name;
  document.getElementById('del-confirm-name').textContent = name;
  document.getElementById('del-name-input').value = '';
  document.getElementById('del-confirm-btn').disabled = true;
  document.getElementById('delete-modal').classList.add('open');
  document.getElementById('del-name-input').focus();
}

function closeDeleteModal() {
  document.getElementById('delete-modal').classList.remove('open');
  document.getElementById('del-name-input').value = '';
  deleteTarget = null;
}

function confirmDelete() {
  if (!deleteTarget) return;
  var name = deleteTarget;
  api('/api/repos/' + encodeURIComponent(name), { method: 'DELETE' }).then(function() {
    toast('Deleted ' + name);
    closeDeleteModal();
    closeRepo();
  }).catch(function(err) { toast('Error: ' + err.message, true); });
}

document.getElementById('del-name-input').addEventListener('input', function() {
  document.getElementById('del-confirm-btn').disabled = (this.value !== deleteTarget);
});
document.getElementById('del-name-input').addEventListener('keydown', function(e) {
  if (e.key === 'Enter' && this.value === deleteTarget) confirmDelete();
  if (e.key === 'Escape') closeDeleteModal();
});

// ── help modal ─────────────────────────────────────────────────────────────
function openHelp() { document.getElementById('help-modal').classList.add('open'); }
function closeHelp() { document.getElementById('help-modal').classList.remove('open'); }

// ── close modals on backdrop ───────────────────────────────────────────────
['repo-modal','help-modal','delete-modal'].forEach(function(id) {
  document.getElementById(id).addEventListener('click', function(e) {
    if (e.target.id === id) e.target.classList.remove('open');
  });
});

// ── user profile ──────────────────────────────────────────────────────────
var currentUser = null;

function getAvatarUrl(name) {
  return 'https://api.dicebear.com/9.x/initials/svg?seed=' + encodeURIComponent(name) + '&backgroundColor=0a0a0a&textColor=00e5a0&fontSize=40';
}

function loadProfile() {
  api('/api/auth/me').then(function(u) {
    currentUser = u;
    var name = u.displayName || u.username;
    document.getElementById('user-pill-name').textContent = name;
    document.getElementById('profile-username').textContent = name;
    document.getElementById('prof-name').value = name;
    var url = getAvatarUrl(name);
    document.getElementById('user-avatar-img-sm').src = url;
    document.getElementById('user-avatar-img-lg').src = url;
  }).catch(function() {});
}

function toggleProfile() {
  var panel = document.getElementById('profile-panel');
  panel.classList.toggle('open');
}

// close profile when clicking outside
document.addEventListener('click', function(e) {
  var panel = document.getElementById('profile-panel');
  var pill = document.getElementById('user-pill');
  if (panel.classList.contains('open') && !panel.contains(e.target) && !pill.contains(e.target)) {
    panel.classList.remove('open');
  }
});

function saveProfile() {
  var displayName = document.getElementById('prof-name').value.trim();
  var curPw = document.getElementById('prof-cur-pw').value;
  var newPw = document.getElementById('prof-new-pw').value;
  var promises = [];

  if (displayName && currentUser && displayName !== (currentUser.displayName || currentUser.username)) {
    promises.push(
      fetch('/api/auth/profile', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ displayName: displayName })
      }).then(function(r) { return r.json(); })
    );
  }

  if (curPw && newPw) {
    promises.push(
      fetch('/api/auth/password', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ current: curPw, newPassword: newPw })
      }).then(function(r) {
        if (!r.ok) return r.json().then(function(d) { throw new Error(d.error); });
        return r.json();
      })
    );
  }

  if (promises.length === 0) {
    toast('Nothing to save');
    return;
  }

  Promise.all(promises).then(function() {
    document.getElementById('prof-cur-pw').value = '';
    document.getElementById('prof-new-pw').value = '';
    if (curPw && newPw) {
      toast('Password changed — signing out\\u2026');
      setTimeout(function() { window.location.href = '/login'; }, 1200);
    } else {
      toast('Profile updated');
      loadProfile();
    }
    document.getElementById('profile-panel').classList.remove('open');
  }).catch(function(err) {
    toast(err.message || 'Save failed', true);
  });
}

function doLogout() {
  fetch('/api/auth/logout', { method:'POST' }).then(function() {
    window.location.href = '/login';
  });
}

// ── init ──────────────────────────────────────────────────────────────────
loadRepos();
loadInfo();
loadProfile();
</script>
</body>
</html>`;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557`);
  console.log(`  \u2551  GitDock running on :${PORT}        \u2551`);
  console.log(`  \u2551  Storage: ${STORAGE} \u2551`);
  console.log(`  \u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D\n`);
});
