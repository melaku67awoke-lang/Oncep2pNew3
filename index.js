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
  notifications: 'notifications.json'
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

  return (
    Number.isFinite(n) &&
    n > 0 &&
    n <= 100000000 &&
    Math.round(n * 100) === n * 100
  );
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

app.use(
  express.static(PUBLIC)
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

app.get(
  '/api/admin/kyc',
  requireAdmin,
  (req, res) => {
    const data = read('kyc')
      .sort(
        (a, b) =>
          String(b.submittedAt).localeCompare(
            String(a.submittedAt)
          )
      );

    res.json(data);
  }
);

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

/* =========================================================
   WALLET
========================================================= */

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

    const reference = String(
      req.body.reference || ''
    ).slice(0, 100);

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

    const transaction = {
      id: id('tx'),
      userId: uid,
      type: 'deposit',
      amount,
      status: 'pending',
      method,
      reference,
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

    const wallet = read(
      'wallets'
    ).find(
      w =>
        String(w.userId) ===
        String(uid)
    );

    if (
      !wallet ||
      Number(wallet.balance || 0) <
        amount
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

    const transaction = {
      id: id('tx'),
      userId: uid,
      type: 'withdrawal',
      amount,
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
        if (
          Number(wallet.balance || 0) <
          Number(transaction.amount)
        ) {
          return res.status(400).json({
            error:
              'User no longer has enough balance'
          });
        }

        wallet.balance = Number(
          (
            Number(wallet.balance) -
            Number(transaction.amount)
          ).toFixed(2)
        );
      }

      write('wallets', wallets);
    }

    transaction.status = status;
    transaction.reason = reason;
    transaction.reviewedAt =
      new Date().toISOString();

    write(
      'transactions',
      transactions
    );

    addNotification(
      transaction.userId,
      'wallet',
      status === 'completed'
        ? 'Wallet request completed'
        : 'Wallet request rejected',
      status === 'completed'
        ? `Your ${transaction.type} request for ${Number(transaction.amount).toFixed(2)} ETB was completed.`
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
    const uid = userId(req);

    const orders = read(
      'orders'
    )
      .filter(
        order =>
          String(order.buyerId) ===
            String(uid) ||
          String(order.sellerId) ===
            String(uid)
      )
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
   ADMIN: USERS / TIERS / FEES / SUPPORT / SETTINGS / REVENUE
========================================================= */

function ensureDataFile(name, initial) {
  const p = path.join(DATA, files[name]);
  if (!fs.existsSync(p)) write(name, initial);
}

// These collections are additive: existing KYC/wallet/order data is preserved.
if (!files.tiers) files.tiers = 'tiers.json';
if (!files.tickets) files.tickets = 'tickets.json';
if (!files.settings) files.settings = 'settings.json';
if (!files.fees) files.fees = 'fees.json';

ensureDataFile('tiers', [
  { tier: 'Tier 0', dailyTransferLimit: 10000, monthlyTransferLimit: 50000, transferFee: 0, withdrawalFee: 0.38, platformFeeUsd: 0.38 },
  { tier: 'Tier 1', dailyTransferLimit: 25000, monthlyTransferLimit: 100000, transferFee: 0, withdrawalFee: 0.38, platformFeeUsd: 0.38 },
  { tier: 'Tier 2', dailyTransferLimit: 100000, monthlyTransferLimit: 500000, transferFee: 0, withdrawalFee: 0.38, platformFeeUsd: 0.38 },
  { tier: 'Tier 3', dailyTransferLimit: 500000, monthlyTransferLimit: 2000000, transferFee: 0, withdrawalFee: 0.38, platformFeeUsd: 0.38 }
]);
ensureDataFile('tickets', []);
ensureDataFile('settings', { maintenanceMode: false, usdToEtb: 0, announcement: '', updatedAt: null });
ensureDataFile('fees', []);

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  let users = read('users').map(u => ({
    userId: u.userId,
    username: u.username,
    fullName: u.fullName,
    createdAt: u.createdAt,
    kycStatus: (read('kyc').find(k => String(k.userId) === String(u.userId)) || {}).status || 'not_submitted',
    wallet: (() => {
      const w = read('wallets').find(x => String(x.userId) === String(u.userId));
      return w ? { balance: Number(w.balance || 0), heldBalance: Number(w.heldBalance || 0), currency: w.currency || 'ETB' } : null;
    })()
  }));
  if (q) users = users.filter(u => `${u.userId} ${u.username} ${u.fullName}`.toLowerCase().includes(q));
  res.json(users);
});

app.get('/api/admin/tiers', requireAdmin, (req, res) => res.json(read('tiers')));

app.put('/api/admin/tiers/:tier', requireAdmin, (req, res) => {
  const tiers = read('tiers');
  const tier = String(req.params.tier);
  const row = tiers.find(t => String(t.tier) === tier);
  if (!row) return res.status(404).json({ error: 'Tier not found' });
  const nums = ['dailyTransferLimit','monthlyTransferLimit','transferFee','withdrawalFee','platformFeeUsd'];
  for (const key of nums) {
    if (req.body[key] !== undefined) {
      const n = Number(req.body[key]);
      if (!Number.isFinite(n) || n < 0 || n > 100000000) return res.status(400).json({ error: `Invalid ${key}` });
      row[key] = Number(n.toFixed(2));
    }
  }
  write('tiers', tiers);
  res.json(row);
});

app.get('/api/admin/settings', requireAdmin, (req, res) => res.json(read('settings')));

app.put('/api/admin/settings', requireAdmin, (req, res) => {
  const current = read('settings');
  const next = {
    maintenanceMode: req.body.maintenanceMode !== undefined ? Boolean(req.body.maintenanceMode) : Boolean(current.maintenanceMode),
    usdToEtb: req.body.usdToEtb !== undefined ? Number(req.body.usdToEtb) : Number(current.usdToEtb || 0),
    announcement: req.body.announcement !== undefined ? String(req.body.announcement).slice(0, 2000) : String(current.announcement || ''),
    updatedAt: new Date().toISOString()
  };
  if (!Number.isFinite(next.usdToEtb) || next.usdToEtb < 0) return res.status(400).json({ error: 'Invalid USD to ETB rate' });
  write('settings', next);
  res.json(next);
});

app.get('/api/admin/tickets', requireAdmin, (req, res) => res.json(read('tickets').sort((a,b) => String(b.createdAt).localeCompare(String(a.createdAt)))));

app.post('/api/admin/tickets/:id/reply', requireAdmin, (req, res) => {
  const tickets = read('tickets');
  const ticket = tickets.find(t => t.id === req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });
  const body = String(req.body.body || '').trim().slice(0, 2000);
  if (!body) return res.status(400).json({ error: 'Reply is required' });
  ticket.messages = Array.isArray(ticket.messages) ? ticket.messages : [];
  ticket.messages.push({ id: id('supmsg'), from: 'admin', body, createdAt: new Date().toISOString() });
  ticket.status = 'open';
  ticket.updatedAt = new Date().toISOString();
  write('tickets', tickets);
  addNotification(ticket.userId, 'support', 'Support replied', 'Support has replied to your ticket.');
  res.json(ticket);
});

app.post('/api/admin/tickets/:id/close', requireAdmin, (req, res) => {
  const tickets = read('tickets');
  const ticket = tickets.find(t => t.id === req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });
  ticket.status = 'closed';
  ticket.updatedAt = new Date().toISOString();
  write('tickets', tickets);
  res.json(ticket);
});

app.get('/api/admin/revenue', requireAdmin, (req, res) => {
  const transactions = read('transactions');
  const feeRows = read('fees');
  const now = new Date();
  const today = now.toISOString().slice(0,10);
  const month = now.toISOString().slice(0,7);
  const totalFees = feeRows.reduce((sum, f) => sum + Number(f.amountUsd || 0), 0);
  const todayFees = feeRows.filter(f => String(f.createdAt || '').slice(0,10) === today).reduce((sum,f) => sum + Number(f.amountUsd || 0), 0);
  const monthFees = feeRows.filter(f => String(f.createdAt || '').slice(0,7) === month).reduce((sum,f) => sum + Number(f.amountUsd || 0), 0);
  const ownerWallet = feeRows.reduce((sum, f) => sum + Number(f.amountUsd || 0), 0);
  res.json({ platformFeeUsd: Number((read('tiers')[0]?.platformFeeUsd || 0.38).toFixed(2)), ownerWalletBalanceUsd: Number(ownerWallet.toFixed(2)), totalFeesCollectedUsd: Number(totalFees.toFixed(2)), todayRevenueUsd: Number(todayFees.toFixed(2)), monthRevenueUsd: Number(monthFees.toFixed(2)), transactionCount: transactions.length });
});

app.post('/api/support/tickets', requireUser, (req, res) => {
  const uid = userId(req);
  const subject = String(req.body.subject || '').trim().slice(0, 200);
  const category = String(req.body.category || 'General Inquiry').trim().slice(0, 80);
  const body = String(req.body.body || '').trim().slice(0, 2000);
  if (!subject || !body) return res.status(400).json({ error: 'Subject and message are required' });
  const tickets = read('tickets');
  const ticket = { id: id('ticket'), userId: uid, category, subject, status: 'open', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), messages: [{ id: id('supmsg'), from: 'user', body, createdAt: new Date().toISOString() }] };
  tickets.push(ticket);
  write('tickets', tickets);
  res.status(201).json(ticket);
});

app.get('/api/support/tickets', requireUser, (req, res) => {
  const uid = userId(req);
  res.json(read('tickets').filter(t => String(t.userId) === String(uid)).sort((a,b) => String(b.updatedAt).localeCompare(String(a.updatedAt))));
});

app.post('/api/support/tickets/:id/message', requireUser, (req, res) => {
  const uid = userId(req);
  const tickets = read('tickets');
  const ticket = tickets.find(t => t.id === req.params.id && String(t.userId) === String(uid));
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });
  if (ticket.status === 'closed') return res.status(400).json({ error: 'Ticket is closed' });
  const body = String(req.body.body || '').trim().slice(0, 2000);
  if (!body) return res.status(400).json({ error: 'Message is required' });
  ticket.messages.push({ id: id('supmsg'), from: 'user', body, createdAt: new Date().toISOString() });
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
