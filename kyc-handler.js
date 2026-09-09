const multer = require('multer');
const path = require('path');
const fs = require('fs');

global.db = global.db || { users: [] };

module.exports = function(app, persistDir) {
  // BUG FIX -- DATA WIPED ON EVERY RESTART: this used to hardcode
  // __dirname (the app's own deploy folder), which Render (and most
  // hosts) discard on every redeploy/restart unless it's on an
  // attached Persistent Disk. It now shares the same PERSIST_DIR
  // index.js resolves (via the DATA_DIR env var once a disk is
  // mounted), so KYC submissions -- and the ID/selfie images
  // uploaded with them -- land in the same durable location as
  // wallets, ads, and everything else, instead of drifting onto a
  // separate, still-ephemeral path.
  const root = persistDir || __dirname;
  const DATA_DIR = path.join(root, 'data');
  const KYC_FILE = path.join(DATA_DIR, 'kyc.json');
  const uploadsDir = path.join(root, 'uploads', 'kyc');

  function readKyc() {
    try {
      if (!fs.existsSync(KYC_FILE)) return [];
      return JSON.parse(fs.readFileSync(KYC_FILE, 'utf8'));
    } catch {
      return [];
    }
  }

  function writeKyc(list) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = KYC_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(list, null, 2), 'utf8');
    fs.renameSync(tmp, KYC_FILE);
  }

  fs.mkdirSync(uploadsDir, { recursive: true });

  const kycStorage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
      cb(null, Date.now() + '-' + file.originalname);
    }
  });
  const uploadKyc = multer({ storage: kycStorage });

  // NOTE: index.js already serves '/uploads' as static from the same
  // PERSIST_DIR/uploads root (registered before this module loads),
  // and that naturally reaches into this uploadsDir subfolder too --
  // no separate static registration needed here.

  // User KYC Submission Endpoint
  app.post('/api/kyc/submit', uploadKyc.fields([{ name: 'idDocument', maxCount: 1 }, { name: 'selfie', maxCount: 1 }]), (req, res) => {
    try {
      const userId = req.body.userId || 'default_user';
      const all = readKyc();
      const existingIndex = all.findIndex(k => String(k.userId) === String(userId));
      const existing = existingIndex >= 0 ? all[existingIndex] : null;

      const record = {
        id: existing ? existing.id : ('kyc_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8)),
        userId,
        fullName: req.body.fullName || req.body.name || 'Verified Applicant',
        idNumber: req.body.idNumber || '123456',
        idType: req.body.idType || 'ID Card',
        idDocument: existing ? existing.idDocument : '',
        selfie: existing ? existing.selfie : '',
        status: 'pending',
        reason: '',
        submittedAt: new Date().toISOString(),
        reviewedAt: null
      };

      if (req.files) {
        if (req.files['idDocument']) {
          record.idDocument = `/uploads/kyc/${req.files['idDocument'][0].filename}`;
        }
        if (req.files['selfie']) {
          record.selfie = `/uploads/kyc/${req.files['selfie'][0].filename}`;
        }
      }

      if (existingIndex >= 0) {
        all[existingIndex] = record;
      } else {
        all.push(record);
      }
      writeKyc(all);

      // Keep the same userId/fullName in the shared users registry so
      // marketplace ads can always resolve the exact seller identity.
      try {
        const USERS_FILE = path.join(DATA_DIR, 'users.json');
        let users = [];
        if (fs.existsSync(USERS_FILE)) {
          try { users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch { users = []; }
        }
        const userIndex = users.findIndex(u =>
          String(u.userId || u.id || '') === String(userId)
        );
        const userRecord = userIndex >= 0 ? users[userIndex] : { id: userId, userId };
        userRecord.id = userRecord.id || userId;
        userRecord.userId = userId;
        userRecord.fullName = record.fullName;
        userRecord.kycStatus = record.status;
        if (userIndex >= 0) users[userIndex] = userRecord;
        else users.push(userRecord);
        fs.mkdirSync(DATA_DIR, { recursive: true });
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
      } catch (syncErr) {
        console.warn('KYC user registry sync failed:', syncErr.message);
      }

      res.json({ success: true, message: 'KYC submitted successfully', user: record });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Endpoint for frontend to check status when reopening the app
  app.get('/api/kyc/status', (req, res) => {
    try {
      const userId = req.query.userId;
      if (!userId) {
        return res.json({ success: true, kycStatus: 'none' });
      }

      const all = readKyc();
      const record = all.find(k => String(k.userId) === String(userId));

      if (!record) {
        return res.json({ success: true, kycStatus: 'none' });
      }

      res.json({ success: true, kycStatus: record.status || 'none', user: record });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Admin: Get KYC Submissions
  app.get('/api/admin/kyc', (req, res) => {
    try {
      const submissions = global.db.users.map(u => ({
        id: u.id || '1',
        userId: u.id || '1',
        fullName: u.fullName || 'Applicant',
        status: u.kycStatus || u.status || 'pending',
        telegramId: u.telegramId || 'N/A',
        idNumber: u.idNumber || '123456',
        idType: u.idType || 'ID Card',
        idDocument: u.idDocumentUrl || u.idDocument || 'https://via.placeholder.com/140x90?text=ID+Card',
        selfie: u.selfieUrl || u.selfie || 'https://via.placeholder.com/140x90?text=Selfie',
        reason: u.reason || ''
      }));

      res.json(submissions);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // NOTE: '/api/admin/wallet-requests' and '/api/admin/orders' are
  // implemented for real in index.js (backed by data/transactions.json
  // and data/orders.json). This file used to also register stub
  // versions of those same routes that always returned an empty array.
  // Because this module is require()'d before those real routes are
  // registered, the stub routes were matched first and permanently
  // shadowed the real ones -- deposits, withdrawals, and orders would
  // never show up in the Admin Dashboard. Removed as a bug fix.

  // Admin: Review KYC (Approve / Reject)
  app.post('/api/admin/kyc/:id/review', (req, res) => {
    const { id } = req.params;
    const { status, reason } = req.body;
    
    try {
      let user = global.db.users.find(u => u.id == id || u.userId == id);
      if (!user) {
        user = { id, userId: id };
        global.db.users.push(user);
      }

      user.kycStatus = status;
      user.status = status;
      user.reason = reason || '';

      if (status === 'approved') {
        user.tier = 2;
        user.escrowEnabled = true;
        user.feeRate = '0.5%';
        user.walletStatus = 'verified';
      }

      res.json({ success: true, user });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
};
