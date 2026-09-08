'use strict';

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();

const PORT = Number(process.env.PORT) || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || 'change-me-admin-key';

const DATA = path.join(__dirname, 'data');
const UPLOADS = path.join(__dirname, 'uploads');
const PUBLIC = path.join(__dirname, 'public');

for (const dir of [DATA, UPLOADS, PUBLIC]) {
  fs.mkdirSync(dir, { recursive: true });
}

/* =========================================================
   DATA STORAGE
========================================================= */

const files = {
  users: 'users.json',
  kyc: 'kyc.json',
  wallets: 'wallets.json',
  transactions: 'transactions.json',
  listings: 'listings.json',
  orders: 'orders.json',
  sessions: 'sessions.json',
  messages: 'messages.json',
  notifications: 'notifications.json',
  tickets: 'tickets.json'
};

function read(name) {
  if (!files[name]) {
    throw new Error(`Unknown data file: ${name}`);
  }

  const p = path.join(DATA, files[name]);

  if (!fs.existsSync(p)) {
    fs.writeFileSync(p, '[]', 'utf8');
  }

  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (err) {
    console.error(`Invalid JSON in ${files[name]}:`, err.message);
    return [];
  }
}

function write(name, value) {
  if (!files[name]) {
    throw new Error(`Unknown data file: ${name}`);
  }

  const p = path.join(DATA, files[name]);
  const tmp = `${p}.tmp`;

  fs.writeFileSync(
    tmp,
    JSON.stringify(value, null, 2),
    'utf8'
  );

  fs.renameSync(tmp, p);
}

function id(prefix) {
  return (
    prefix +
    '_' +
    Date.now().toString(36) +
    crypto.randomBytes(4).toString('hex')
  );
}

/* =========================================================
   AUTH HELPERS
========================================================= */

function tokenFrom(req) {
  const header = String(req.get('authorization') || '');

  if (!header.startsWith('Bearer ')) {
    return '';
  }

  return header.slice(7).trim();
}

function userId(req) {
  const token = tokenFrom(req);

  if (!token) {
    return '';
  }

  const session = read('sessions').find(
    s =>
      s.token === token &&
      s.expiresAt &&
      new Date(s.expiresAt).getTime() > Date.now()
  );

  return session ? String(session.userId) : '';
}

function requireUser(req, res, next) {
  if (!userId(req)) {
    return res.status(401).json({
      error: 'Please log in'
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (req.get('x-admin-key') !== ADMIN_KEY) {
    return res.status(403).json({
      error: 'Admin access denied'
    });
  }

  next();
}

function requireVerified(req, res, next) {
  const uid = userId(req);

  const kyc = read('kyc').find(
    item => String(item.userId) === String(uid)
  );

  if (!kyc || kyc.status !== 'approved') {
    return res.status(403).json({
      error: 'KYC approval required'
    });
  }

  next();
}

/* =========================================================
   SECURITY / PASSWORDS
========================================================= */

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString('hex');

  return {
    salt,
    hash
  };
}

function verifyPassword(password, salt, hash) {
  try {
    const calculated = crypto.scryptSync(
      password,
      salt,
      64
    );

    const stored = Buffer.from(hash, 'hex');

    return (
      calculated.length === stored.length &&
      crypto.timingSafeEqual(calculated, stored)
    );
  } catch {
    return false;
  }
}

function safeUser(user) {
  if (!user) return null;

  return {
    userId: user.userId,
    username: user.username,
    fullName: user.fullName,
    createdAt: user.createdAt
  };
}

/* =========================================================
   NOTIFICATIONS
========================================================= */

function addNotification(
  uid,
  type,
  title,
  body,
  orderId = ''
) {
  const notifications = read('notifications');

  notifications.push({
    id: id('ntf'),
    userId: uid,
    type,
    title,
    body,
    orderId,
    read: false,
    createdAt: new Date().toISOString()
  });

  write('notifications', notifications);
}

/* =========================================================
   WALLET HELPERS
========================================================= */

function validAmount(value) {
  const n = Number(value);

  /*
    BUG FIX: comparing Math.round(n * 100) to n * 100 with strict
    equality breaks on ordinary 2-decimal values due to IEEE754
    floating-point representation -- e.g. 72.73 - 0.38 = 72.35, but
    72.35 * 100 evaluates to 7234.999999999999 in JS, not 7235. That
    made perfectly valid amounts (like the Withdraw modal's "Max"
    button, which computes balance - fee) get rejected as invalid.
    A small tolerance makes the comparison float-safe while still
    enforcing "up to 2 decimal places".
  */
  return (
    Number.isFinite(n) &&
    n > 0 &&
    n <= 100000000 &&
    Math.abs(Math.round(n * 100) - n * 100) < 1e-6
  );
}

/*
  Flat platform withdrawal fee, in USDT. The user-facing UI (see
  public/index.html "Flat fee: $0.38 USDT" and the admin "Tier & Fee"
  panel) has always advertised this fee, but the backend never
  actually calculated or applied it -- withdrawals were processed
  fee-free. Defined here so it's applied consistently.
*/
const WITHDRAWAL_FEE_USDT = 0.38;

/*
  DEPOSIT LAUNCH-BLOCKER FIX: every user was shown the exact same
  hardcoded BEP20 address in the Deposit modal, with nothing tying an
  incoming transfer to a specific account. Real per-user blockchain
  addresses would require full HD-wallet key derivation and custody
  infrastructure this dev build doesn't have (and generating
  look-alike addresses with no real private key behind them would be
  actively dangerous -- any funds sent there would be unrecoverable).
  Instead, the platform's one real receiving address stays exactly
  the same (unchanged, still safe to send funds to), and each account
  is given its own short, stable deposit reference derived from its
  userId. The reference is deterministic (same account always gets
  the same one) so it doesn't need its own storage, and different
  accounts get different references.
*/
const DEPOSIT_ADDRESS =
  '0x8e54105bed3243e1ca44a0cccc6b62cf2bff9df4';

/*
  V62 FIX -- BUG 1 (unique deposit reference per request):
  Every account used to get one fixed, deterministic reference
  forever (a hash of its userId). That meant a second deposit from
  the same account was indistinguishable from the first, and admin
  had no way to tell which specific transfer a given credit was for.
  References are now minted fresh, per deposit REQUEST, in the
  DEP-XXXXXX shape, and stored on that request's transaction record
  -- so every deposit a user makes gets its own one-time code, and
  crediting one by reference can never be confused with another.
*/
function generateDepositReference() {
  const existing = new Set(
    read('transactions')
      .filter(tx => tx.type === 'deposit' && tx.reference)
      .map(tx => String(tx.reference).toUpperCase())
  );

  const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

  let reference;

  do {
    let suffix = '';

    for (let i = 0; i < 6; i++) {
      suffix += ALPHABET[
        crypto.randomInt(ALPHABET.length)
      ];
    }

    reference = 'DEP-' + suffix;
  } while (existing.has(reference));

  return reference;
}

/*
  Resolves a deposit reference (as typed by an admin, or scanned off
  an incoming transfer memo) back to the specific pending deposit
  transaction it belongs to, so a credit can only ever be applied to
  the one request that reference was actually issued for.
*/
function findPendingDepositByReference(reference) {
  const target = String(reference || '').trim().toUpperCase();

  if (!target) {
    return null;
  }

  return read('transactions').find(
    tx =>
      tx.type === 'deposit' &&
      tx.status === 'pending' &&
      String(tx.reference || '').toUpperCase() === target
  ) || null;
}

function ensureWallet(uid) {
  const wallets = read('wallets');

  let wallet = wallets.find(
    w => String(w.userId) === String(uid)
  );

  if (!wallet) {
    wallet = {
      id: id('wal'),
      userId: uid,
      balance: 0,
      heldBalance: 0,
      currency: 'ETB'
    };

    wallets.push(wallet);
    write('wallets', wallets);
  }

  return wallet;
}

/* =========================================================
   FILE UPLOADS
========================================================= */

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, UPLOADS);
    },

    filename: (req, file, cb) => {
      const extension = path.extname(
        file.originalname || ''
      ).toLowerCase();

      cb(
        null,
        `${id('doc')}${extension}`
      );
    }
  }),

  limits: {
    fileSize: 8 * 1024 * 1024
  },

  fileFilter: (req, file, cb) => {
    const allowed = [
      'image/jpeg',
      'image/png',
      'application/pdf'
    ];

    if (!allowed.includes(file.mimetype)) {
      return cb(
        new Error(
          'Only JPG, PNG and PDF files are allowed'
        )
      );
    }

    cb(null, true);
  }
});

/* =========================================================
   APP MIDDLEWARE
========================================================= */

app.disable('x-powered-by');

app.use(
  cors({
    origin: true,
    credentials: false
  })
);

app.use(
  express.json({
    limit: '1mb'
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: '1mb'
  })
);

/*
  Public uploads are kept because the existing application
  expects /uploads/... paths.

  IMPORTANT:
  For a real production KYC system, identity documents
  should be stored privately and served only after admin
  authentication.
*/
app.use(
  '/uploads',
  express.static(UPLOADS)
);

/*
  V62 FIX -- BUG 7 (stale JS/cached wallet code on Render):
  express.static() has no cache headers by default in this app, but
  browsers and some CDNs will still opportunistically cache
  index.html/admin.html and any static JS aggressively once a
  Cache-Control header is absent (falling back to heuristic
  caching). Explicitly marking the HTML entry points as no-cache
  forces every client to re-fetch the current build after each
  deploy instead of serving a stale copy of the wallet code from
  before this hotfix.
*/
app.use(
  express.static(PUBLIC, {
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('.html')) {
        res.setHeader(
          'Cache-Control',
          'no-cache, no-store, must-revalidate'
        );
      }
    }
  })
);

/* =========================================================
   HEALTH
========================================================= */

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    app: 'Once P2P',
    time: new Date().toISOString()
  });
});

/* =========================================================
   AUTHENTICATION
========================================================= */

app.post('/api/auth/register', (req, res) => {
  try {
    const username = String(
      req.body.username || ''
    ).trim().slice(0, 40);

    const fullName = String(
      req.body.fullName || ''
    ).trim().slice(0, 100);

    const password = String(
      req.body.password || ''
    );

    if (
      !username ||
      !fullName ||
      password.length < 8
    ) {
      return res.status(400).json({
        error:
          'Full name, username and password (8+ characters) are required'
      });
    }

    const users = read('users');

    const exists = users.some(
      u =>
        String(u.username).toLowerCase() ===
        username.toLowerCase()
    );

    if (exists) {
      return res.status(409).json({
        error: 'Username already exists'
      });
    }

    const uid =
      'u_' + crypto.randomUUID();

    const passwordData =
      hashPassword(password);

    const user = {
      id: id('usr'),
      userId: uid,
      username,
      fullName,
      passwordHash: passwordData.hash,
      passwordSalt: passwordData.salt,
      createdAt: new Date().toISOString()
    };

    users.push(user);
    write('users', users);

    ensureWallet(uid);

    const token = crypto
      .randomBytes(32)
      .toString('hex');

    const sessions = read('sessions');

    sessions.push({
      id: id('ses'),
      token,
      userId: uid,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(
        Date.now() +
          30 * 24 * 60 * 60 * 1000
      ).toISOString()
    });

    write('sessions', sessions);

    res.status(201).json({
      token,
      user: safeUser(user)
    });
  } catch (err) {
    console.error('Register error:', err);

    res.status(500).json({
      error: 'Registration failed'
    });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const username = String(
      req.body.username || ''
    ).trim();

    const password = String(
      req.body.password || ''
    );

    const user = read('users').find(
      u =>
        String(u.username).toLowerCase() ===
        username.toLowerCase()
    );

    if (
      !user ||
      !user.passwordHash ||
      !verifyPassword(
        password,
        user.passwordSalt,
        user.passwordHash
      )
    ) {
      return res.status(401).json({
        error: 'Invalid username or password'
      });
    }

    const token = crypto
      .randomBytes(32)
      .toString('hex');

    const sessions = read('sessions');

    sessions.push({
      id: id('ses'),
      token,
      userId: user.userId,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(
        Date.now() +
          30 * 24 * 60 * 60 * 1000
      ).toISOString()
    });

    write('sessions', sessions);

    res.json({
      token,
      user: safeUser(user)
    });
  } catch (err) {
    console.error('Login error:', err);

    res.status(500).json({
      error: 'Login failed'
    });
  }
});

app.post(
  '/api/auth/logout',
  requireUser,
  (req, res) => {
    const token = tokenFrom(req);

    const sessions = read('sessions')
      .filter(s => s.token !== token);

    write('sessions', sessions);

    res.json({
      ok: true
    });
  }
);

/* =========================================================
   USER PROFILE
========================================================= */

app.post('/api/users', (req, res) => {
  res.status(410).json({
    error: 'Use /api/auth/register'
  });
});

app.get(
  '/api/me',
  requireUser,
  (req, res) => {
    const uid = userId(req);

    const user = read('users').find(
      u => String(u.userId) === String(uid)
    );

    const kyc = read('kyc').find(
      k => String(k.userId) === String(uid)
    );

    const wallet = read('wallets').find(
      w => String(w.userId) === String(uid)
    );

    const safeKyc = kyc
      ? {
          id: kyc.id,
          status: kyc.status,
          reason: kyc.reason || '',
          submittedAt: kyc.submittedAt,
          reviewedAt: kyc.reviewedAt
        }
      : {
          status: 'not_submitted'
        };

    res.json({
      user: safeUser(user),
      kyc: safeKyc,
      wallet: wallet
        ? {
            balance: Number(wallet.balance || 0),
            heldBalance: Number(
              wallet.heldBalance || 0
            ),
            currency:
              wallet.currency || 'ETB'
          }
        : null
    });
  }
);

/* =========================================================
   KYC
========================================================= */

app.post(
  '/api/kyc',
  requireUser,
  upload.fields([
    {
      name: 'idDocument',
      maxCount: 1
    },
    {
      name: 'selfie',
      maxCount: 1
    }
  ]),
  (req, res) => {
    try {
      const uid = userId(req);

      const fullName = String(
        req.body.fullName || ''
      ).trim();

      const dob = String(
        req.body.dob || ''
      ).trim();

      const address = String(
        req.body.address || ''
      ).trim();

      const idType = String(
        req.body.idType || ''
      ).trim();

      const idNumber = String(
        req.body.idNumber || ''
      ).trim();

      if (
        !fullName ||
        !dob ||
        !address ||
        !idType ||
        !idNumber
      ) {
        return res.status(400).json({
          error: 'All KYC fields are required'
        });
      }

      if (
        !req.files ||
        !req.files.idDocument ||
        !req.files.idDocument[0] ||
        !req.files.selfie ||
        !req.files.selfie[0]
      ) {
        return res.status(400).json({
          error:
            'ID document and selfie are required'
        });
      }

      const all = read('kyc');

      const old = all.find(
        k => String(k.userId) === String(uid)
      );

      if (
        old &&
        old.status === 'approved'
      ) {
        return res.status(400).json({
          error: 'KYC already approved'
        });
      }

      /*
        Remove old uploaded documents.
      */
      if (old) {
        for (const field of [
          'idDocument',
          'selfie'
        ]) {
          const oldPath = old[field];

          if (
            oldPath &&
            oldPath.startsWith('/uploads/')
          ) {
            const filePath = path.join(
              UPLOADS,
              path.basename(oldPath)
            );

            if (fs.existsSync(filePath)) {
              try {
                fs.unlinkSync(filePath);
              } catch {}
            }
          }
        }
      }

      const record = {
        id:
          old && old.id
            ? old.id
            : id('kyc'),

        userId: uid,
        fullName,
        dob,
        address,
        idType,
        idNumber,

        idDocument:
          '/uploads/' +
          req.files.idDocument[0].filename,

        selfie:
          '/uploads/' +
          req.files.selfie[0].filename,

        status: 'pending',
        reason: '',
        submittedAt:
          new Date().toISOString(),
        reviewedAt: null
      };

      const next = all.filter(
        k =>
          String(k.userId) !==
          String(uid)
      );

      next.push(record);

      write('kyc', next);

      /*
        Update user's display name.
      */
      const users = read('users');

      const user = users.find(
        u =>
          String(u.userId) ===
          String(uid)
      );

      if (user) {
        user.fullName = fullName;
        write('users', users);
      }

      res.status(201).json({
        id: record.id,
        status: record.status,
        submittedAt: record.submittedAt
      });
    } catch (err) {
      console.error('KYC error:', err);

      res.status(500).json({
        error: 'KYC submission failed'
      });
    }
  }
);

app.get('/api/admin/kyc', requireAdmin, (req, res) => {
  const users = read('users');
  const list = read('kyc').sort((a,b)=>new Date(b.submittedAt)-new Date(a.submittedAt)).map(k=>{
    const u = users.find(x=>String(x.userId)===String(k.userId)) || {};
    return {
      ...k,
      fullName: k.fullName || u.fullName || '',
      telegramId: u.telegramId || u.telegram || '',
      username: u.username || ''
    };
  });
  res.json(list);
});

// ===== V120 KYC ADMIN PATCH =====
// (kept for backward compatibility with any path-param callers)
app.get('/api/kyc/status/:userId', (req,res)=>{
  const item = read('kyc').find(k=>String(k.userId)===String(req.params.userId));
  if(!item) return res.json({status:'not_submitted'});
  res.json(item);
});

/*
  V62 FIX -- BUG 3 (KYC session persistence):
  The frontend's checkKYCStatusOnStartup() calls
  GET /api/kyc/status?userId=... (a query string) and expects a
  response shaped like { success: true, kycStatus: 'approved' }.
  The only route that existed was GET /api/kyc/status/:userId (a path
  param) returning the raw KYC record with a `status` field and no
  `success` flag -- a completely different URL and a completely
  different response shape. Express never matched the query-string
  request to the path-param route, so every startup check silently
  404'd, the frontend's catch() fired, and even fully KYC-approved
  users were dumped back on the Landing Page every time the app was
  reopened. This route matches exactly what the frontend calls and
  returns exactly the shape it expects, so approved users now land
  directly on Marketplace/Home and never see Landing/Registration
  again until they actually log out or a session expires.
*/
app.get('/api/kyc/status', (req, res) => {
  const uid = String(req.query.userId || '').trim();

  if (!uid) {
    return res.json({ success: true, kycStatus: 'none' });
  }

  const item = read('kyc').find(
    k => String(k.userId) === String(uid)
  );

  res.json({
    success: true,
    kycStatus: item ? item.status : 'none',
    reason: item ? item.reason || '' : ''
  });
});


app.post(
  '/api/admin/kyc/:id/review',
  requireAdmin,
  (req, res) => {
    const status = String(
      req.body.status || ''
    );

    const reason = String(
      req.body.reason || ''
    ).slice(0, 500);

    if (
      !['approved', 'rejected'].includes(
        status
      )
    ) {
      return res.status(400).json({
        error:
          'status must be approved or rejected'
      });
    }

    const all = read('kyc');

    const kyc = all.find(
      k => k.id === req.params.id
    );

    if (!kyc) {
      return res.status(404).json({
        error: 'KYC not found'
      });
    }

    kyc.status = status;
    kyc.reason = reason;
    kyc.reviewedAt =
      new Date().toISOString();

    write('kyc', all);

    addNotification(
      kyc.userId,
      'kyc_update',
      status === 'approved'
        ? 'KYC approved'
        : 'KYC rejected',
      status === 'approved'
        ? 'Your KYC verification has been approved.'
        : `Your KYC verification was rejected.${reason ? ' Reason: ' + reason : ''}`
    );

    res.json(kyc);
  }
);

/*
  LAUNCH-BLOCKER FIX: this must be required here, before the
  SPA fallback / 404 API handler / error handler are registered
  below. Those catch-all handlers intercept every request that
  doesn't match an earlier route, so any route added by
  kyc-handler.js after them (e.g. POST /api/kyc/submit) would
  otherwise always return 404 and never run.
*/
require('./kyc-handler')(app);

/* =========================================================
   WALLET
========================================================= */

/*
  WITHDRAWAL LAUNCH-BLOCKER FIX: the wallet endpoints below require
  an authenticated session (requireUser) tied to a KYC-approved
  userId (requireVerified). The existing sign-up flow only ever
  creates a locally-generated identity for KYC (see kyc-handler.js /
  the KYC screen in public/index.html) and never establishes a real
  login session, so there was previously no way for the browser to
  call any wallet endpoint at all -- this is why the withdraw button
  could only ever fake success client-side.
  This endpoint mints a real session for an existing KYC-approved
  identity without altering the KYC flow itself: given a userId that
  already has an approved KYC record, it returns a valid bearer
  token for that exact same userId (a session doesn't require a
  matching users.json entry -- see userId() above). It grants no
  more access than requireVerified already allows.
*/
app.post('/api/wallet/session', (req, res) => {
  try {
    const uid = String(req.body.userId || '').trim();

    if (!uid) {
      return res.status(400).json({
        error: 'userId is required'
      });
    }

    const kyc = read('kyc').find(
      item => String(item.userId) === String(uid)
    );

    if (!kyc || kyc.status !== 'approved') {
      return res.status(403).json({
        error: 'KYC approval required before using the wallet'
      });
    }

    ensureWallet(uid);

    const token = crypto
      .randomBytes(32)
      .toString('hex');

    const sessions = read('sessions');

    sessions.push({
      id: id('ses'),
      token,
      userId: uid,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(
        Date.now() + 30 * 24 * 60 * 60 * 1000
      ).toISOString()
    });

    write('sessions', sessions);

    res.status(201).json({
      token,
      userId: uid
    });
  } catch (err) {
    res.status(500).json({
      error: 'Server error'
    });
  }
});

/*
  Returns the (single, real) platform deposit address. A per-deposit
  reference is no longer handed out here -- it's generated when the
  user actually submits a deposit request (POST
  /api/wallet/deposit-request below), so every request gets its own
  unique DEP-XXXXXX code instead of one fixed code being reused for
  every transfer an account ever makes.
*/
app.get(
  '/api/wallet/deposit-address',
  requireUser,
  requireVerified,
  (req, res) => {
    res.json({
      address: DEPOSIT_ADDRESS
    });
  }
);

app.get(
  '/api/wallet',
  requireUser,
  requireVerified,
  (req, res) => {
    const wallet = ensureWallet(
      userId(req)
    );

    res.json({
      id: wallet.id,
      userId: wallet.userId,
      balance: Number(wallet.balance || 0),
      heldBalance: Number(
        wallet.heldBalance || 0
      ),
      currency:
        wallet.currency || 'ETB'
    });
  }
);

app.get(
  '/api/wallet/transactions',
  requireUser,
  requireVerified,
  (req, res) => {
    const uid = userId(req);

    const transactions = read(
      'transactions'
    )
      .filter(
        tx =>
          String(tx.userId) ===
          String(uid)
      )
      .reverse();

    res.json(transactions);
  }
);

/* =========================================================
   ADMIN WALLET CREDIT
========================================================= */

app.post(
  '/api/wallet/demo-credit',
  requireAdmin,
  (req, res) => {
    const uid = String(
      req.body.userId || ''
    ).trim();

    const amount = Number(
      req.body.amount
    );

    const note = String(
      req.body.note || 'Demo credit'
    ).slice(0, 300);

    if (
      !uid ||
      !validAmount(amount)
    ) {
      return res.status(400).json({
        error:
          'Valid amount with up to 2 decimals is required'
      });
    }

    const users = read('users');

    if (
      !users.some(
        u =>
          String(u.userId) ===
          String(uid)
      )
    ) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    const wallets = read('wallets');

    let wallet = wallets.find(
      w =>
        String(w.userId) ===
        String(uid)
    );

    if (!wallet) {
      wallet = {
        id: id('wal'),
        userId: uid,
        balance: 0,
        heldBalance: 0,
        currency: 'ETB'
      };

      wallets.push(wallet);
    }

    wallet.balance = Number(
      (
        Number(wallet.balance || 0) +
        amount
      ).toFixed(2)
    );

    write('wallets', wallets);

    const transaction = {
      id: id('tx'),
      userId: uid,
      type: 'admin_credit',
      amount,
      status: 'completed',
      note,
      createdAt:
        new Date().toISOString()
    };

    const transactions =
      read('transactions');

    transactions.push(transaction);

    write(
      'transactions',
      transactions
    );

    addNotification(
      uid,
      'wallet',
      'Wallet credited',
      `Your wallet was credited with ${amount.toFixed(2)} ETB.`
    );

    res.json({
      wallet: {
        balance: wallet.balance,
        currency: wallet.currency
      },
      transaction
    });
  }
);

/*
  V62 FIX -- BUG 1 (deposit crediting by reference):
  Every account shares one BEP20 address, so the only thing that
  ties an incoming transfer to a specific request is the unique
  DEP-XXXXXX reference generated for it by POST
  /api/wallet/deposit-request. This endpoint is a fast path for an
  admin who wants to credit a deposit by typing in that reference
  directly (rather than browsing the full pending-requests list in
  the dashboard): it looks up the one PENDING deposit transaction
  that reference belongs to and credits exactly that request -- the
  same crediting logic used by
  POST /api/admin/wallet-requests/:id/review. A reference that
  doesn't match any pending request (wrong code, already credited,
  already rejected) credits nothing.
*/
app.post(
  '/api/admin/wallet/credit-by-reference',
  requireAdmin,
  (req, res) => {
    const reference = String(
      req.body.reference || ''
    ).trim();

    if (!reference) {
      return res.status(400).json({
        error: 'A deposit reference is required'
      });
    }

    const transaction = findPendingDepositByReference(
      reference
    );

    if (!transaction) {
      return res.status(404).json({
        error:
          'No pending deposit matches that reference'
      });
    }

    const amount = Number(transaction.amount);
    const uid = transaction.userId;

    const wallets = read('wallets');

    let target = wallets.find(
      w => String(w.userId) === String(uid)
    );

    if (!target) {
      target = {
        id: id('wal'),
        userId: uid,
        balance: 0,
        heldBalance: 0,
        currency: 'ETB'
      };

      wallets.push(target);
    }

    target.balance = Number(
      (
        Number(target.balance || 0) + amount
      ).toFixed(2)
    );

    write('wallets', wallets);

    const transactions = read('transactions');

    const stored = transactions.find(
      tx => tx.id === transaction.id
    );

    stored.status = 'completed';
    stored.reviewedAt = new Date().toISOString();

    write('transactions', transactions);

    addNotification(
      uid,
      'wallet',
      'Deposit received',
      `Your deposit of ${amount.toFixed(2)} was credited (ref: ${reference}).`
    );

    res.json({
      userId: uid,
      wallet: {
        balance: target.balance,
        currency: target.currency
      },
      transaction: stored
    });
  }
);

/* =========================================================
   DEPOSIT REQUEST
========================================================= */

app.post(
  '/api/wallet/deposit-request',
  requireUser,
  requireVerified,
  (req, res) => {
    const uid = userId(req);

    const amount = Number(
      req.body.amount
    );

    const method = String(
      req.body.method || 'manual'
    ).slice(0, 50);

    if (!validAmount(amount)) {
      return res.status(400).json({
        error:
          'Enter a valid amount with up to 2 decimals'
      });
    }

    const pending = read(
      'transactions'
    ).find(
      tx =>
        String(tx.userId) ===
          String(uid) &&
        tx.type === 'deposit' &&
        tx.status === 'pending'
    );

    if (pending) {
      return res.status(400).json({
        error:
          'You already have a pending deposit request'
      });
    }

    /*
      V62 FIX: the reference is minted here, server-side, and is
      unique to this specific request -- never accepted from the
      client and never reused across requests (see BUG 1 above).
    */
    const reference = generateDepositReference();

    const transaction = {
      id: id('tx'),
      userId: uid,
      type: 'deposit',
      amount,
      status: 'pending',
      method,
      reference,
      address: DEPOSIT_ADDRESS,
      createdAt:
        new Date().toISOString()
    };

    const transactions =
      read('transactions');

    transactions.push(transaction);

    write(
      'transactions',
      transactions
    );

    res.status(201).json(
      transaction
    );
  }
);

/* =========================================================
   WITHDRAW REQUEST
========================================================= */

app.post(
  '/api/wallet/withdraw-request',
  requireUser,
  requireVerified,
  (req, res) => {
    const uid = userId(req);

    const amount = Number(
      req.body.amount
    );

    const method = String(
      req.body.method || 'bank'
    ).slice(0, 50);

    const account = String(
      req.body.account || ''
    ).slice(0, 120);

    if (!validAmount(amount)) {
      return res.status(400).json({
        error:
          'Enter a valid amount with up to 2 decimals'
      });
    }

    if (amount <= 0) {
      return res.status(400).json({
        error:
          'Enter an amount greater than 0'
      });
    }

    const wallets = read('wallets');

    const wallet = wallets.find(
      w =>
        String(w.userId) ===
        String(uid)
    );

    /*
      The withdrawal fee is a flat platform charge on top of the
      amount the user wants to receive. The full total (amount + fee)
      is locked out of the available balance immediately when the
      request is created -- mirroring how buy/sell escrow already
      holds funds -- rather than waiting until an admin approves it.
      This prevents the same funds from being spent twice while a
      withdrawal is pending, and matches the "deduct immediately"
      requirement for this flow.
    */
    const fee = WITHDRAWAL_FEE_USDT;

    const totalDeduction = Number(
      (amount + fee).toFixed(2)
    );

    if (
      !wallet ||
      Number(wallet.balance || 0) <
        totalDeduction
    ) {
      return res.status(400).json({
        error:
          'Insufficient wallet balance'
      });
    }

    const pending = read(
      'transactions'
    ).find(
      tx =>
        String(tx.userId) ===
          String(uid) &&
        tx.type === 'withdrawal' &&
        tx.status === 'pending'
    );

    if (pending) {
      return res.status(400).json({
        error:
          'You already have a pending withdrawal request'
      });
    }

    wallet.balance = Number(
      (Number(wallet.balance || 0) - totalDeduction).toFixed(2)
    );

    wallet.heldBalance = Number(
      (Number(wallet.heldBalance || 0) + totalDeduction).toFixed(2)
    );

    write('wallets', wallets);

    const transaction = {
      id: id('tx'),
      userId: uid,
      type: 'withdrawal',
      amount,
      fee,
      totalDeduction,
      status: 'pending',
      method,
      account,
      createdAt:
        new Date().toISOString()
    };

    const transactions =
      read('transactions');

    transactions.push(transaction);

    write(
      'transactions',
      transactions
    );

    res.status(201).json(
      transaction
    );
  }
);

/* =========================================================
   ADMIN WALLET REQUESTS
========================================================= */

app.get(
  '/api/admin/wallet-requests',
  requireAdmin,
  (req, res) => {
    const requests = read(
      'transactions'
    )
      .filter(
        tx =>
          tx.type === 'deposit' ||
          tx.type === 'withdrawal'
      )
      .reverse();

    res.json(requests);
  }
);

app.post(
  '/api/admin/wallet-requests/:id/review',
  requireAdmin,
  (req, res) => {
    const status = String(
      req.body.status || ''
    );

    const reason = String(
      req.body.reason || ''
    ).slice(0, 300);

    if (
      !['completed', 'rejected'].includes(
        status
      )
    ) {
      return res.status(400).json({
        error:
          'status must be completed or rejected'
      });
    }

    const transactions =
      read('transactions');

    const transaction =
      transactions.find(
        tx =>
          tx.id === req.params.id
      );

    if (!transaction) {
      return res.status(404).json({
        error: 'Request not found'
      });
    }

    if (
      !['deposit', 'withdrawal'].includes(
        transaction.type
      ) ||
      transaction.status !== 'pending'
    ) {
      return res.status(400).json({
        error:
          'Request is not pending'
      });
    }

    if (status === 'completed') {
      const wallets = read('wallets');

      let wallet = wallets.find(
        w =>
          String(w.userId) ===
          String(transaction.userId)
      );

      if (!wallet) {
        wallet = {
          id: id('wal'),
          userId: transaction.userId,
          balance: 0,
          heldBalance: 0,
          currency: 'ETB'
        };

        wallets.push(wallet);
      }

      if (
        transaction.type ===
        'deposit'
      ) {
        wallet.balance = Number(
          (
            Number(wallet.balance || 0) +
            Number(transaction.amount)
          ).toFixed(2)
        );
      } else {
        /*
          Withdrawals are debited (amount + fee) from the wallet
          immediately when the request is created (see
          POST /api/wallet/withdraw-request) and parked in
          heldBalance. Approving here just releases the hold -- the
          funds already left `balance` at request time, so it must
          not be deducted a second time.
        */
        const locked = Number(
          transaction.totalDeduction != null
            ? transaction.totalDeduction
            : transaction.amount
        );

        wallet.heldBalance = Number(
          (
            Number(wallet.heldBalance || 0) - locked
          ).toFixed(2)
        );

        if (wallet.heldBalance < 0) {
          wallet.heldBalance = 0;
        }
      }

      write('wallets', wallets);
    } else if (
      status === 'rejected' &&
      transaction.type === 'withdrawal'
    ) {
      /*
        Refund the hold placed at request time back onto the
        available balance.
      */
      const wallets = read('wallets');

      const wallet = wallets.find(
        w =>
          String(w.userId) ===
          String(transaction.userId)
      );

      if (wallet) {
        const locked = Number(
          transaction.totalDeduction != null
            ? transaction.totalDeduction
            : transaction.amount
        );

        wallet.balance = Number(
          (
            Number(wallet.balance || 0) + locked
          ).toFixed(2)
        );

        wallet.heldBalance = Number(
          (
            Number(wallet.heldBalance || 0) - locked
          ).toFixed(2)
        );

        if (wallet.heldBalance < 0) {
          wallet.heldBalance = 0;
        }

        write('wallets', wallets);
      }
    }

    transaction.status = status;
    transaction.reason = reason;
    transaction.reviewedAt =
      new Date().toISOString();

    write(
      'transactions',
      transactions
    );

    const completedMessage =
      status === 'completed' &&
      transaction.type === 'withdrawal' &&
      transaction.fee
        ? `Your withdrawal of ${Number(transaction.amount).toFixed(2)} USDT was completed. A $${Number(transaction.fee).toFixed(2)} fee was also deducted (total ${Number(transaction.totalDeduction).toFixed(2)} USDT).`
        : `Your ${transaction.type} request for ${Number(transaction.amount).toFixed(2)} ETB was completed.`;

    addNotification(
      transaction.userId,
      'wallet',
      status === 'completed'
        ? 'Wallet request completed'
        : 'Wallet request rejected',
      status === 'completed'
        ? completedMessage
        : `Your ${transaction.type} request was rejected.${reason ? ' Reason: ' + reason : ''}`
    );

    res.json(transaction);
  }
);

/* =========================================================
   WALLET TRANSFER
========================================================= */

app.post(
  '/api/wallet/transfer',
  requireUser,
  requireVerified,
  (req, res) => {
    const from = userId(req);

    const to = String(
      req.body.toUserId || ''
    ).trim();

    const amount = Number(
      req.body.amount
    );

    if (
      !to ||
      to === from ||
      !validAmount(amount)
    ) {
      return res.status(400).json({
        error:
          'Valid recipient and amount required'
      });
    }

    const recipientKyc =
      read('kyc').find(
        k =>
          String(k.userId) ===
            String(to) &&
          k.status === 'approved'
      );

    if (!recipientKyc) {
      return res.status(400).json({
        error:
          'Recipient must have approved KYC'
      });
    }

    const wallets = read('wallets');

    const sender = wallets.find(
      w =>
        String(w.userId) ===
        String(from)
    );

    const recipient = wallets.find(
      w =>
        String(w.userId) ===
        String(to)
    );

    if (!sender || !recipient) {
      return res.status(404).json({
        error:
          'Sender or recipient wallet not found'
      });
    }

    if (
      Number(sender.balance || 0) <
      amount
    ) {
      return res.status(400).json({
        error:
          'Insufficient balance'
      });
    }

    sender.balance = Number(
      (
        Number(sender.balance) -
        amount
      ).toFixed(2)
    );

    recipient.balance = Number(
      (
        Number(recipient.balance) +
        amount
      ).toFixed(2)
    );

    write('wallets', wallets);

    const now =
      new Date().toISOString();

    const transactions =
      read('transactions');

    transactions.push(
      {
        id: id('tx'),
        userId: from,
        type: 'transfer_out',
        amount,
        status: 'completed',
        toUserId: to,
        createdAt: now
      },
      {
        id: id('tx'),
        userId: to,
        type: 'transfer_in',
        amount,
        status: 'completed',
        fromUserId: from,
        createdAt: now
      }
    );

    write(
      'transactions',
      transactions
    );

    addNotification(
      to,
      'wallet',
      'Money received',
      `You received ${amount.toFixed(2)} ETB from another user.`
    );

    res.json({
      ok: true,
      sender: {
        balance: sender.balance,
        currency: sender.currency
      },
      recipient: {
        balance: recipient.balance,
        currency: recipient.currency
      }
    });
  }
);

/* =========================================================
   MARKETPLACE LISTINGS
========================================================= */

app.get(
  '/api/listings',
  (req, res) => {
    const category = String(
      req.query.category || ''
    ).trim();

    const query = String(
      req.query.q || ''
    )
      .trim()
      .toLowerCase();

    let listings = read(
      'listings'
    ).filter(
      listing =>
        listing.status === 'active'
    );

    if (category) {
      listings = listings.filter(
        listing =>
          String(
            listing.category
          ) === category
      );
    }

    if (query) {
      listings = listings.filter(
        listing =>
          (
            String(listing.title) +
            ' ' +
            String(
              listing.description
            )
          )
            .toLowerCase()
            .includes(query)
      );
    }

    res.json(
      listings.reverse()
    );
  }
);

app.post(
  '/api/listings',
  requireUser,
  requireVerified,
  (req, res) => {
    const title = String(
      req.body.title || ''
    ).trim();

    const description = String(
      req.body.description || ''
    ).trim();

    const price = Number(
      req.body.price
    );

    const category = String(
      req.body.category || 'Other'
    ).trim();

    if (
      !title ||
      !description ||
      !validAmount(price)
    ) {
      return res.status(400).json({
        error:
          'Title, description and valid price required'
      });
    }

    const listing = {
      id: id('lst'),
      sellerId: userId(req),
      title: title.slice(0, 120),
      description:
        description.slice(0, 1000),
      price: Number(
        price.toFixed(2)
      ),
      category:
        category.slice(0, 50) ||
        'Other',
      status: 'active',
      createdAt:
        new Date().toISOString()
    };

    const listings =
      read('listings');

    listings.push(listing);

    write(
      'listings',
      listings
    );

    res.status(201).json(
      listing
    );
  }
);

app.delete(
  '/api/listings/:id',
  requireUser,
  requireVerified,
  (req, res) => {
    const listings =
      read('listings');

    const listing =
      listings.find(
        l => l.id === req.params.id
      );

    if (!listing) {
      return res.status(404).json({
        error: 'Listing not found'
      });
    }

    if (
      String(listing.sellerId) !==
      String(userId(req))
    ) {
      return res.status(403).json({
        error:
          'Only the seller can remove this listing'
      });
    }

    if (
      listing.status !== 'active'
    ) {
      return res.status(400).json({
        error:
          'Listing is no longer active'
      });
    }

    listing.status = 'cancelled';

    write(
      'listings',
      listings
    );

    res.json(listing);
  }
);

/* =========================================================
   ORDERS / ESCROW
========================================================= */

function getOrder(orderId) {
  return read('orders').find(
    order => order.id === orderId
  );
}

/*
  V62 FIX -- ORDERS BUG: orders used to just sit at whatever status they
  were created with forever -- there was no code path that ever expired
  one, so a stuck order stayed "ongoing" indefinitely and the only real
  countdown data (shipBy / completeBy) was never actually enforced.
  This scans for orders whose real deadline has passed and moves them to
  'cancelled' (refunding the buyer's held escrow, same as a manual
  cancel), so GET /api/orders always reflects the true, current state --
  the client never has to (and no longer does) guess or invent this.
*/
function autoExpireOrders() {
  const orders = read('orders');
  const wallets = read('wallets');
  const transactions = read('transactions');

  const now = Date.now();
  let ordersChanged = false;
  let walletsChanged = false;
  let txChanged = false;

  orders.forEach(order => {
    if (!['paid_escrow', 'shipped', 'delivered'].includes(order.status)) {
      return;
    }

    const deadline =
      order.status === 'paid_escrow'
        ? order.shipBy
        : order.completeBy;

    if (!deadline || new Date(deadline).getTime() > now) {
      return;
    }

    const buyerWallet = wallets.find(
      w => String(w.userId) === String(order.buyerId)
    );

    if (
      buyerWallet &&
      Number(buyerWallet.heldBalance || 0) >= Number(order.amount)
    ) {
      buyerWallet.heldBalance = Number(
        (Number(buyerWallet.heldBalance) - Number(order.amount)).toFixed(2)
      );
      buyerWallet.balance = Number(
        (Number(buyerWallet.balance || 0) + Number(order.amount)).toFixed(2)
      );
      walletsChanged = true;
    }

    order.status = 'cancelled';
    order.cancelledBy = 'system';
    order.cancelReason = 'expired';
    order.updatedAt = new Date().toISOString();
    ordersChanged = true;

    transactions.push({
      id: id('tx'),
      userId: order.buyerId,
      type: 'marketplace_escrow_refund',
      amount: Number(order.amount),
      status: 'completed',
      orderId: order.id,
      createdAt: new Date().toISOString()
    });
    txChanged = true;

    addNotification(
      order.buyerId,
      'order_update',
      'Order expired',
      'The order expired and your escrow was refunded.',
      order.id
    );

    addNotification(
      order.sellerId,
      'order_update',
      'Order expired',
      'The order expired and was automatically cancelled.',
      order.id
    );
  });

  if (ordersChanged) write('orders', orders);
  if (walletsChanged) write('wallets', wallets);
  if (txChanged) write('transactions', transactions);
}

app.post(
  '/api/orders',
  requireUser,
  requireVerified,
  (req, res) => {
    const buyer = userId(req);

    const listingId = String(
      req.body.listingId || ''
    );

    const listings =
      read('listings');

    const listing =
      listings.find(
        l =>
          l.id === listingId &&
          l.status === 'active'
      );

    if (!listing) {
      return res.status(404).json({
        error:
          'Listing not found or already reserved'
      });
    }

    if (
      String(listing.sellerId) ===
      String(buyer)
    ) {
      return res.status(400).json({
        error:
          'You cannot buy your own listing'
      });
    }

    const sellerKyc =
      read('kyc').find(
        k =>
          String(k.userId) ===
            String(listing.sellerId) &&
          k.status === 'approved'
      );

    if (!sellerKyc) {
      return res.status(400).json({
        error:
          'Seller is not currently KYC verified'
      });
    }

    const wallets =
      read('wallets');

    const buyerWallet =
      wallets.find(
        w =>
          String(w.userId) ===
          String(buyer)
      );

    const sellerWallet =
      wallets.find(
        w =>
          String(w.userId) ===
          String(listing.sellerId)
      );

    if (
      !buyerWallet ||
      Number(buyerWallet.balance || 0) <
        Number(listing.price)
    ) {
      return res.status(400).json({
        error:
          'Insufficient available wallet balance'
      });
    }

    if (!sellerWallet) {
      return res.status(400).json({
        error:
          'Seller wallet not found'
      });
    }

    const amount = Number(
      listing.price
    );

    buyerWallet.balance = Number(
      (
        Number(buyerWallet.balance) -
        amount
      ).toFixed(2)
    );

    buyerWallet.heldBalance =
      Number(
        (
          Number(
            buyerWallet.heldBalance || 0
          ) + amount
        ).toFixed(2)
      );

    listing.status = 'reserved';

    write(
      'wallets',
      wallets
    );

    write(
      'listings',
      listings
    );

    const now =
      new Date().toISOString();

    const order = {
      id: id('ord'),
      listingId,
      buyerId: buyer,
      sellerId: listing.sellerId,
      amount,
      title: listing.title,
      status: 'paid_escrow',
      createdAt: now,
      updatedAt: now,

      shipBy: new Date(
        Date.now() +
          48 * 60 * 60 * 1000
      ).toISOString(),

      completeBy: new Date(
        Date.now() +
          7 * 24 * 60 * 60 * 1000
      ).toISOString(),

      expiresAt: new Date(
        Date.now() +
          7 * 24 * 60 * 60 * 1000
      ).toISOString(),

      shippingNote: '',
      trackingNumber: '',
      carrier: '',
      evidence: []
    };

    const orders =
      read('orders');

    orders.push(order);

    write(
      'orders',
      orders
    );

    const transactions =
      read('transactions');

    transactions.push({
      id: id('tx'),
      userId: buyer,
      type:
        'marketplace_escrow_hold',
      amount,
      status: 'held',
      orderId: order.id,
      createdAt: now
    });

    write(
      'transactions',
      transactions
    );

    addNotification(
      listing.sellerId,
      'order_update',
      'New order',
      `Someone purchased your listing "${listing.title}".`,
      order.id
    );

    res.status(201).json(
      order
    );
  }
);

app.get(
  '/api/orders',
  requireUser,
  requireVerified,
  (req, res) => {
    // V62 FIX -- ORDERS BUG: flush any order whose real deadline has
    // passed to 'cancelled' before we read the list, so what we return
    // is always the current, true state -- never a countdown that has
    // to be faked or restarted on the client.
    autoExpireOrders();

    const uid = userId(req);
    const users = read('users');

    const orders = read('orders')
      .filter(
        order =>
          String(order.buyerId) === String(uid) ||
          String(order.sellerId) === String(uid)
      )
      .filter(order => {
        // V62 FIX -- ORDERS BUG: if the other party on this order was a
        // sample/demo account that has since been deleted, don't show
        // it -- there's no one left to trade with and the counterparty
        // details are gone.
        const counterpartyId =
          String(order.buyerId) === String(uid)
            ? order.sellerId
            : order.buyerId;

        return users.some(
          u => String(u.userId) === String(counterpartyId)
        );
      })
      .map(order => {
        const isBuyer = String(order.buyerId) === String(uid);
        const counterpartyId = isBuyer ? order.sellerId : order.buyerId;
        const counterparty = users.find(
          u => String(u.userId) === String(counterpartyId)
        );

        const deadline =
          order.status === 'paid_escrow'
            ? order.shipBy
            : ['shipped', 'delivered'].includes(order.status)
            ? order.completeBy
            : null;

        return Object.assign({}, order, {
          role: isBuyer ? 'buyer' : 'seller',
          counterpartyName: counterparty
            ? counterparty.fullName
            : 'Unknown',
          deadline
        });
      })
      .reverse();

    res.json(orders);
  }
);

/* =========================================================
   SHIP ORDER
========================================================= */

app.post(
  '/api/orders/:id/ship',
  requireUser,
  requireVerified,
  (req, res) => {
    const uid = userId(req);

    const orders =
      read('orders');

    const order =
      orders.find(
        o => o.id === req.params.id
      );

    if (!order) {
      return res.status(404).json({
        error: 'Order not found'
      });
    }

    if (
      String(order.sellerId) !==
      String(uid)
    ) {
      return res.status(403).json({
        error:
          'Only the seller can mark an order shipped'
      });
    }

    if (
      order.status !==
      'paid_escrow'
    ) {
      return res.status(400).json({
        error:
          'Order is not ready for shipping'
      });
    }

    order.status = 'shipped';

    order.shippingNote =
      String(
        req.body.note || ''
      ).slice(0, 300);

    order.trackingNumber =
      String(
        req.body.trackingNumber || ''
      )
        .trim()
        .slice(0, 100);

    order.carrier =
      String(
        req.body.carrier || ''
      )
        .trim()
        .slice(0, 80);

    order.shippedAt =
      new Date().toISOString();

    order.updatedAt =
      new Date().toISOString();

    write(
      'orders',
      orders
    );

    addNotification(
      order.buyerId,
      'order_update',
      'Order shipped',
      'The seller marked your order as shipped.',
      order.id
    );

    res.json(order);
  }
);

/* =========================================================
   MARK DELIVERED
========================================================= */

app.post(
  '/api/orders/:id/deliver',
  requireUser,
  requireVerified,
  (req, res) => {
    const uid = userId(req);

    const orders =
      read('orders');

    const order =
      orders.find(
        o => o.id === req.params.id
      );

    if (!order) {
      return res.status(404).json({
        error: 'Order not found'
      });
    }

    if (
      String(order.sellerId) !==
      String(uid)
    ) {
      return res.status(403).json({
        error:
          'Only the seller can mark delivery'
      });
    }

    if (
      order.status !== 'shipped'
    ) {
      return res.status(400).json({
        error:
          'Order must be shipped first'
      });
    }

    order.status = 'delivered';

    order.deliveredAt =
      new Date().toISOString();

    order.updatedAt =
      new Date().toISOString();

    write(
      'orders',
      orders
    );

    addNotification(
      order.buyerId,
      'order_update',
      'Order delivered',
      'The seller marked your order as delivered.',
      order.id
    );

    res.json(order);
  }
);

/* =========================================================
   CONFIRM RECEIPT / RELEASE ESCROW
========================================================= */

app.post(
  '/api/orders/:id/confirm',
  requireUser,
  requireVerified,
  (req, res) => {
    const uid = userId(req);

    const orders =
      read('orders');

    const order =
      orders.find(
        o => o.id === req.params.id
      );

    if (!order) {
      return res.status(404).json({
        error: 'Order not found'
      });
    }

    if (
      String(order.buyerId) !==
      String(uid)
    ) {
      return res.status(403).json({
        error:
          'Only the buyer can confirm receipt'
      });
    }

    if (
      ![
        'shipped',
        'delivered'
      ].includes(order.status)
    ) {
      return res.status(400).json({
        error:
          'Order is not ready for confirmation'
      });
    }

    const wallets =
      read('wallets');

    const buyerWallet =
      wallets.find(
        w =>
          String(w.userId) ===
          String(order.buyerId)
      );

    const sellerWallet =
      wallets.find(
        w =>
          String(w.userId) ===
          String(order.sellerId)
      );

    if (
      !buyerWallet ||
      !sellerWallet ||
      Number(
        buyerWallet.heldBalance || 0
      ) < Number(order.amount)
    ) {
      return res.status(400).json({
        error:
          'Escrow funds are unavailable'
      });
    }

    const amount =
      Number(order.amount);

    buyerWallet.heldBalance =
      Number(
        (
          Number(
            buyerWallet.heldBalance
          ) - amount
        ).toFixed(2)
      );

    sellerWallet.balance =
      Number(
        (
          Number(
            sellerWallet.balance || 0
          ) + amount
        ).toFixed(2)
      );

    order.status = 'completed';

    order.updatedAt =
      new Date().toISOString();

    write(
      'wallets',
      wallets
    );

    write(
      'orders',
      orders
    );

    const transactions =
      read('transactions');

    const now =
      new Date().toISOString();

    transactions.push(
      {
        id: id('tx'),
        userId: order.buyerId,
        type:
          'marketplace_escrow_release',
        amount,
        status: 'completed',
        orderId: order.id,
        createdAt: now
      },
      {
        id: id('tx'),
        userId: order.sellerId,
        type: 'marketplace_sale',
        amount,
        status: 'completed',
        orderId: order.id,
        createdAt: now
      }
    );

    write(
      'transactions',
      transactions
    );

    const listings =
      read('listings');

    const listing =
      listings.find(
        l =>
          l.id === order.listingId
      );

    if (listing) {
      listing.status = 'sold';
      write(
        'listings',
        listings
      );
    }

    addNotification(
      order.sellerId,
      'order_update',
      'Payment released',
      `The buyer confirmed receipt. ${amount.toFixed(2)} ETB has been released to your wallet.`,
      order.id
    );

    res.json(order);
  }
);

/* =========================================================
   CANCEL ORDER
========================================================= */

app.post(
  '/api/orders/:id/cancel',
  requireUser,
  requireVerified,
  (req, res) => {
    const uid = userId(req);

    const orders =
      read('orders');

    const order =
      orders.find(
        o => o.id === req.params.id
      );

    if (!order) {
      return res.status(404).json({
        error: 'Order not found'
      });
    }

    if (
      ![
        order.buyerId,
        order.sellerId
      ].includes(uid)
    ) {
      return res.status(403).json({
        error: 'Not allowed'
      });
    }

    if (
      ![
        'paid_escrow',
        'shipped'
      ].includes(order.status)
    ) {
      return res.status(400).json({
        error:
          'Order cannot be cancelled at this stage'
      });
    }

    const wallets =
      read('wallets');

    const buyerWallet =
      wallets.find(
        w =>
          String(w.userId) ===
          String(order.buyerId)
      );

    if (
      !buyerWallet ||
      Number(
        buyerWallet.heldBalance || 0
      ) < Number(order.amount)
    ) {
      return res.status(400).json({
        error:
          'Escrow funds are unavailable'
      });
    }

    const amount =
      Number(order.amount);

    buyerWallet.heldBalance =
      Number(
        (
          Number(
            buyerWallet.heldBalance
          ) - amount
        ).toFixed(2)
      );

    buyerWallet.balance =
      Number(
        (
          Number(
            buyerWallet.balance || 0
          ) + amount
        ).toFixed(2)
      );

    order.status = 'cancelled';
    order.cancelledBy = uid;

    order.updatedAt =
      new Date().toISOString();

    write(
      'wallets',
      wallets
    );

    write(
      'orders',
      orders
    );

    const listings =
      read('listings');

    const listing =
      listings.find(
        l =>
          l.id === order.listingId
      );

    if (listing) {
      listing.status = 'active';

      write(
        'listings',
        listings
      );
    }

    const transactions =
      read('transactions');

    transactions.push({
      id: id('tx'),
      userId: order.buyerId,
      type:
        'marketplace_escrow_refund',
      amount,
      status: 'completed',
      orderId: order.id,
      createdAt:
        new Date().toISOString()
    });

    write(
      'transactions',
      transactions
    );

    addNotification(
      order.buyerId,
      'order_update',
      'Order cancelled',
      'The order was cancelled and your escrow was refunded.',
      order.id
    );

    addNotification(
      order.sellerId,
      'order_update',
      'Order cancelled',
      'The order was cancelled.',
      order.id
    );

    res.json(order);
  }
);

/* =========================================================
   DISPUTES
========================================================= */

app.post(
  '/api/orders/:id/dispute',
  requireUser,
  requireVerified,
  (req, res) => {
    const uid = userId(req);

    const orders =
      read('orders');

    const order =
      orders.find(
        o => o.id === req.params.id
      );

    if (!order) {
      return res.status(404).json({
        error: 'Order not found'
      });
    }

    if (
      ![
        order.buyerId,
        order.sellerId
      ].includes(uid)
    ) {
      return res.status(403).json({
        error: 'Not allowed'
      });
    }

    if (
      [
        'completed',
        'cancelled',
        'disputed',
        'refunded'
      ].includes(order.status)
    ) {
      return res.status(400).json({
        error:
          'Order cannot be disputed'
      });
    }

    order.status = 'disputed';

    order.disputeBy = uid;

    order.disputeReason =
      String(
        req.body.reason || ''
      ).slice(0, 500);

    order.updatedAt =
      new Date().toISOString();

    write(
      'orders',
      orders
    );

    addNotification(
      order.buyerId === uid
        ? order.sellerId
        : order.buyerId,
      'dispute',
      'Trade disputed',
      `A dispute was opened for trade ${order.id}.`,
      order.id
    );

    res.json(order);
  }
);

/* =========================================================
   ADMIN ORDERS
========================================================= */

app.get(
  '/api/admin/orders',
  requireAdmin,
  (req, res) => {
    // V62 FIX -- ORDERS BUG: keep the admin view in sync with the same
    // real-expiry logic as the user-facing endpoint.
    autoExpireOrders();

    res.json(
      read('orders').reverse()
    );
  }
);

/* =========================================================
   ADMIN DISPUTE RESOLUTION
========================================================= */

app.post(
  '/api/admin/orders/:id/resolve',
  requireAdmin,
  (req, res) => {
    const decision = String(
      req.body.decision || ''
    );

    const reason = String(
      req.body.reason || ''
    ).slice(0, 500);

    if (
      ![
        'refund_buyer',
        'release_seller'
      ].includes(decision)
    ) {
      return res.status(400).json({
        error:
          'Decision must be refund_buyer or release_seller'
      });
    }

    const orders =
      read('orders');

    const order =
      orders.find(
        o => o.id === req.params.id
      );

    if (!order) {
      return res.status(404).json({
        error: 'Order not found'
      });
    }

    if (
      order.status !== 'disputed'
    ) {
      return res.status(400).json({
        error:
          'Order is not disputed'
      });
    }

    const wallets =
      read('wallets');

    const buyerWallet =
      wallets.find(
        w =>
          String(w.userId) ===
          String(order.buyerId)
      );

    const sellerWallet =
      wallets.find(
        w =>
          String(w.userId) ===
          String(order.sellerId)
      );

    const amount =
      Number(order.amount);

    if (
      !buyerWallet ||
      !sellerWallet ||
      Number(
        buyerWallet.heldBalance || 0
      ) < amount
    ) {
      return res.status(400).json({
        error:
          'Escrow funds are unavailable'
      });
    }

    buyerWallet.heldBalance =
      Number(
        (
          Number(
            buyerWallet.heldBalance
          ) - amount
        ).toFixed(2)
      );

    if (
      decision ===
      'refund_buyer'
    ) {
      buyerWallet.balance =
        Number(
          (
            Number(
              buyerWallet.balance || 0
            ) + amount
          ).toFixed(2)
        );

      order.status = 'refunded';
    } else {
      sellerWallet.balance =
        Number(
          (
            Number(
              sellerWallet.balance || 0
            ) + amount
          ).toFixed(2)
        );

      order.status = 'completed';
    }

    order.adminDecision =
      decision;

    order.adminReason =
      reason;

    order.updatedAt =
      new Date().toISOString();

    write(
      'wallets',
      wallets
    );

    write(
      'orders',
      orders
    );

    const transactions =
      read('transactions');

    transactions.push({
      id: id('tx'),
      userId:
        decision === 'refund_buyer'
          ? order.buyerId
          : order.sellerId,
      type:
        decision === 'refund_buyer'
          ? 'marketplace_dispute_refund'
          : 'marketplace_dispute_release',
      amount,
      status: 'completed',
      orderId: order.id,
      createdAt:
        new Date().toISOString()
    });

    write(
      'transactions',
      transactions
    );

    const listings =
      read('listings');

    const listing =
      listings.find(
        l =>
          l.id === order.listingId
      );

    if (listing) {
      listing.status =
        decision === 'refund_buyer'
          ? 'active'
          : 'sold';

      write(
        'listings',
        listings
      );
    }

    addNotification(
      decision === 'refund_buyer'
        ? order.buyerId
        : order.sellerId,
      'dispute',
      'Dispute resolved',
      decision === 'refund_buyer'
        ? `The dispute was resolved in your favor. ${amount.toFixed(2)} ETB was refunded.`
        : `The dispute was resolved in favor of the seller. ${amount.toFixed(2)} ETB was released.`,
      order.id
    );

    res.json(order);
  }
);

/* =========================================================
   ADMIN ORDER EVIDENCE
========================================================= */

app.get(
  '/api/admin/orders/:id/evidence',
  requireAdmin,
  (req, res) => {
    const order =
      getOrder(req.params.id);

    if (!order) {
      return res.status(404).json({
        error: 'Order not found'
      });
    }

    res.json(
      (order.evidence || []).map(
        evidence => ({
          id: evidence.id,
          userId: evidence.userId,
          path: evidence.path,
          createdAt:
            evidence.createdAt
        })
      )
    );
  }
);

/* =========================================================
   NOTIFICATIONS
========================================================= */

app.get(
  '/api/notifications',
  requireUser,
  (req, res) => {
    const uid = userId(req);

    const notifications =
      read('notifications')
        .filter(
          n =>
            String(n.userId) ===
            String(uid)
        )
        .reverse()
        .slice(0, 100);

    res.json(notifications);
  }
);

app.post(
  '/api/notifications/:id/read',
  requireUser,
  (req, res) => {
    const uid = userId(req);

    const notifications =
      read('notifications');

    const notification =
      notifications.find(
        n =>
          n.id === req.params.id &&
          String(n.userId) ===
            String(uid)
      );

    if (!notification) {
      return res.status(404).json({
        error:
          'Notification not found'
      });
    }

    notification.read = true;

    write(
      'notifications',
      notifications
    );

    res.json(notification);
  }
);

/* =========================================================
   TRADE CHAT
========================================================= */

app.get(
  '/api/orders/:id/messages',
  requireUser,
  requireVerified,
  (req, res) => {
    const order =
      getOrder(req.params.id);

    const uid = userId(req);

    if (
      !order ||
      ![
        order.buyerId,
        order.sellerId
      ].includes(uid)
    ) {
      return res.status(404).json({
        error: 'Trade not found'
      });
    }

    const messages =
      read('messages')
        .filter(
          message =>
            message.orderId ===
            order.id
        )
        .map(message => ({
          id: message.id,
          fromUserId:
            message.fromUserId,
          body: message.body,
          createdAt:
            message.createdAt
        }));

    res.json(messages);
  }
);

app.post(
  '/api/orders/:id/messages',
  requireUser,
  requireVerified,
  (req, res) => {
    const order =
      getOrder(req.params.id);

    const uid = userId(req);

    if (
      !order ||
      ![
        order.buyerId,
        order.sellerId
      ].includes(uid)
    ) {
      return res.status(404).json({
        error: 'Trade not found'
      });
    }

    const body = String(
      req.body.body || ''
    )
      .trim()
      .slice(0, 1000);

    if (!body) {
      return res.status(400).json({
        error: 'Message is required'
      });
    }

    const message = {
      id: id('msg'),
      orderId: order.id,
      fromUserId: uid,
      body,
      createdAt:
        new Date().toISOString()
    };

    const messages =
      read('messages');

    messages.push(message);

    write(
      'messages',
      messages
    );

    const recipient =
      uid === order.buyerId
        ? order.sellerId
        : order.buyerId;

    addNotification(
      recipient,
      'trade_message',
      'New trade message',
      'You received a new message in a trade.',
      order.id
    );

    res.status(201).json(
      message
    );
  }
);

/* =========================================================
   TRADE EVIDENCE
========================================================= */

app.post(
  '/api/orders/:id/evidence',
  requireUser,
  requireVerified,
  upload.single('evidence'),
  (req, res) => {
    const order =
      getOrder(req.params.id);

    const uid = userId(req);

    if (
      !order ||
      ![
        order.buyerId,
        order.sellerId
      ].includes(uid)
    ) {
      return res.status(404).json({
        error: 'Trade not found'
      });
    }

    if (!req.file) {
      return res.status(400).json({
        error:
          'Evidence file required'
      });
    }

    order.evidence =
      order.evidence || [];

    const evidence = {
      id: id('ev'),
      userId: uid,
      path:
        '/uploads/' +
        req.file.filename,
      createdAt:
        new Date().toISOString()
    };

    order.evidence.push(
      evidence
    );

    const orders =
      read('orders');

    const index =
      orders.findIndex(
        o => o.id === order.id
      );

    if (index === -1) {
      return res.status(404).json({
        error: 'Order not found'
      });
    }

    orders[index] = order;

    write(
      'orders',
      orders
    );

    res.status(201).json({
      id: evidence.id,
      createdAt:
        evidence.createdAt
    });
  }
);

/* =========================================================
   ORDER EXPIRATION
========================================================= */

function expireOrders() {
  try {
    const orders =
      read('orders');

    const wallets =
      read('wallets');

    const listings =
      read('listings');

    const transactions =
      read('transactions');

    let changed = false;

    const now = Date.now();

    for (const order of orders) {
      if (
        ![
          'paid_escrow',
          'shipped'
        ].includes(order.status)
      ) {
        continue;
      }

      if (!order.expiresAt) {
        continue;
      }

      const expiry =
        new Date(
          order.expiresAt
        ).getTime();

      if (
        !Number.isFinite(expiry) ||
        expiry > now
      ) {
        continue;
      }

      const buyerWallet =
        wallets.find(
          w =>
            String(w.userId) ===
            String(order.buyerId)
        );

      if (
        !buyerWallet ||
        Number(
          buyerWallet.heldBalance || 0
        ) < Number(order.amount)
      ) {
        continue;
      }

      const amount =
        Number(order.amount);

      buyerWallet.heldBalance =
        Number(
          (
            Number(
              buyerWallet.heldBalance || 0
            ) - amount
          ).toFixed(2)
        );

      buyerWallet.balance =
        Number(
          (
            Number(
              buyerWallet.balance || 0
            ) + amount
          ).toFixed(2)
        );

      order.status = 'expired';

      order.updatedAt =
        new Date().toISOString();

      transactions.push({
        id: id('tx'),
        userId: order.buyerId,
        type:
          'marketplace_expiry_refund',
        amount,
        status: 'completed',
        orderId: order.id,
        createdAt:
          new Date().toISOString()
      });

      const listing =
        listings.find(
          l =>
            l.id === order.listingId
        );

      if (listing) {
        listing.status = 'active';
      }

      addNotification(
        order.buyerId,
        'order_update',
        'Trade expired',
        'The trade deadline passed and your escrow was refunded.',
        order.id
      );

      addNotification(
        order.sellerId,
        'order_update',
        'Trade expired',
        'The trade deadline passed and the order was cancelled.',
        order.id
      );

      changed = true;
    }

    if (changed) {
      write(
        'orders',
        orders
      );

      write(
        'wallets',
        wallets
      );

      write(
        'listings',
        listings
      );

      write(
        'transactions',
        transactions
      );
    }
  } catch (err) {
    console.error(
      'Order expiration error:',
      err
    );
  }
}

/*
  Check expired orders every 30 seconds.
*/
setInterval(
  expireOrders,
  30 * 1000
);

/*
  Run once when server starts.
*/
expireOrders();

/* =========================================================
   V62 FIX -- BUG 4 (Help Center / Contact Center):
   Support tickets used to live only in a browser-side JS array
   (`supportTickets` in public/index.html) -- nothing was ever sent
   to the server. That meant tickets vanished on refresh, the admin
   dashboard's Help Center section had no data source at all (hence
   the blank page), and there was no way for an admin to reply.
   These routes give tickets a real, persistent home and let admin
   see, reply to, close, and reopen them, with replies visible back
   in the user's own Contact Center.
========================================================= */

/*
  Ticket ownership uses the same lightweight identity the rest of
  the app already relies on before a full wallet session exists
  (see kyc-handler.js and the "kycUserId" localStorage key) --
  no separate login is required just to ask for help.
*/
app.post('/api/tickets', (req, res) => {
  const uid = String(req.body.userId || '').trim();
  const category = String(req.body.category || 'General').slice(0, 60);
  const subject = String(req.body.subject || '').trim().slice(0, 200);
  const message = String(req.body.message || '').trim().slice(0, 5000);

  if (!uid) {
    return res.status(400).json({ error: 'userId is required' });
  }

  if (!subject || !message) {
    return res.status(400).json({ error: 'Subject and message are required' });
  }

  const ticket = {
    id: id('tkt'),
    userId: uid,
    category,
    subject,
    message,
    status: 'open',
    replies: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  const tickets = read('tickets');
  tickets.push(ticket);
  write('tickets', tickets);

  res.status(201).json(ticket);
});

/*
  A user's own tickets, so the Contact Center can render current
  status and any admin replies -- including ones added after the
  ticket was first created.
*/
app.get('/api/tickets', (req, res) => {
  const uid = String(req.query.userId || '').trim();

  if (!uid) {
    return res.json([]);
  }

  const tickets = read('tickets')
    .filter(t => String(t.userId) === uid)
    .reverse();

  res.json(tickets);
});

app.get('/api/admin/tickets', requireAdmin, (req, res) => {
  res.json(read('tickets').reverse());
});

app.post('/api/admin/tickets/:id/reply', requireAdmin, (req, res) => {
  const message = String(req.body.message || '').trim().slice(0, 5000);

  if (!message) {
    return res.status(400).json({ error: 'Reply message is required' });
  }

  const tickets = read('tickets');
  const ticket = tickets.find(t => t.id === req.params.id);

  if (!ticket) {
    return res.status(404).json({ error: 'Ticket not found' });
  }

  if (!Array.isArray(ticket.replies)) {
    ticket.replies = [];
  }

  ticket.replies.push({
    from: 'admin',
    message,
    createdAt: new Date().toISOString()
  });

  // A reply re-opens a closed ticket, since the conversation is active again.
  ticket.status = 'open';
  ticket.updatedAt = new Date().toISOString();

  write('tickets', tickets);

  addNotification(
    ticket.userId,
    'support',
    'Support replied to your ticket',
    message.slice(0, 200)
  );

  res.json(ticket);
});

app.post('/api/admin/tickets/:id/status', requireAdmin, (req, res) => {
  const status = String(req.body.status || '');

  if (!['open', 'closed'].includes(status)) {
    return res.status(400).json({ error: 'status must be open or closed' });
  }

  const tickets = read('tickets');
  const ticket = tickets.find(t => t.id === req.params.id);

  if (!ticket) {
    return res.status(404).json({ error: 'Ticket not found' });
  }

  ticket.status = status;
  ticket.updatedAt = new Date().toISOString();

  write('tickets', tickets);

  res.json(ticket);
});

/* =========================================================
   ADMIN PAGE
========================================================= */

app.get(
  '/admin',
  (req, res) => {
    const adminFile =
      path.join(
        PUBLIC,
        'admin.html'
      );

    if (!fs.existsSync(adminFile)) {
      return res.status(404).send(
        'admin.html not found'
      );
    }

    res.sendFile(adminFile);
  }
);

/* =========================================================
   SPA FALLBACK
========================================================= */

/*
  This intentionally uses app.use() instead of
  app.get('*') so it works with both Express 4
  and Express 5.
*/
app.use(
  (req, res, next) => {
    if (
      req.method !== 'GET' ||
      req.path.startsWith('/api/')
    ) {
      return next();
    }

    const indexFile =
      path.join(
        PUBLIC,
        'index.html'
      );

    if (!fs.existsSync(indexFile)) {
      return res.status(404).send(
        'index.html not found'
      );
    }

    res.sendFile(indexFile);
  }
);

/* =========================================================
   404 API HANDLER
========================================================= */

app.use(
  (req, res) => {
    if (
      req.path.startsWith('/api/')
    ) {
      return res.status(404).json({
        error: 'API endpoint not found'
      });
    }

    res.status(404).send(
      'Page not found'
    );
  }
);

/* =========================================================
   MULTER / GENERAL ERROR HANDLER
========================================================= */

app.use(
  (err, req, res, next) => {
    console.error(
      'Server error:',
      err
    );

    if (
      err instanceof multer.MulterError
    ) {
      if (
        err.code ===
        'LIMIT_FILE_SIZE'
      ) {
        return res.status(400).json({
          error:
            'File is too large. Maximum size is 8 MB.'
        });
      }

      return res.status(400).json({
        error: err.message
      });
    }

    if (
      err &&
      err.message &&
      (
        err.message.includes(
          'Only JPG, PNG'
        )
      )
    ) {
      return res.status(400).json({
        error: err.message
      });
    }

    res.status(500).json({
      error: 'Internal server error'
    });
  }
);

/* =========================================================
   START SERVER
========================================================= */

app.listen(
  PORT,
  () => {
    console.log(
      `Once P2P running on port ${PORT}`
    );

    if (
      ADMIN_KEY ===
      'change-me-admin-key'
    ) {
      console.warn(
        'WARNING: Set the ADMIN_KEY environment variable before production use.'
      );
    }
  }
);

/*
  V61 CLEANUP: three legacy KYC routes ("V123 REAL KYC PATCH") used to
  be registered here, after app.listen() and -- more importantly --
  after the SPA fallback and the catch-all 404 API handler above.
  Express matches routes in registration order, so every request to
  these paths was already being intercepted and answered by the
  catch-all 404 handler (registered earlier) before it could ever
  reach this code; it was 100% dead/unreachable and also lacked the
  requireAdmin check and notification/audit fields the real
  '/api/admin/kyc' and '/api/admin/kyc/:id/review' routes above have.
  Removed as unreachable duplicate code -- no behavior changes,
  since it never ran.
*/
