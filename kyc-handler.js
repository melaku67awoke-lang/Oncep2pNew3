const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Persist KYC submissions to the same data/kyc.json store that the admin
// dashboard (via index.js) reads from, so submissions actually show up there.
const DATA_DIR = path.join(__dirname, 'data');
const KYC_FILE = path.join(DATA_DIR, 'kyc.json');

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

global.db = global.db || { users: [] };

module.exports = function(app) {
  const uploadsDir = path.join(__dirname, 'public', 'uploads');
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

  app.use('/uploads', require('express').static(path.join(__dirname, 'public', 'uploads')));

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
          record.idDocument = `/uploads/${req.files['idDocument'][0].filename}`;
        }
        if (req.files['selfie']) {
          record.selfie = `/uploads/${req.files['selfie'][0].filename}`;
        }
      }

      if (existingIndex >= 0) {
        all[existingIndex] = record;
      } else {
        all.push(record);
      }
      writeKyc(all);

      res.json({ success: true, message: 'KYC submitted successfully', user: record });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Endpoint for frontend to check status when reopening the app
  app.get('/api/kyc/status', (req, res) => {
    try {
      const userId = req.query.userId || 'default_user';
      const all = readKyc();
      let record = all.find(k => String(k.userId) === String(userId));

      if (!record && all.length > 0) {
        record = all[all.length - 1]; // Return latest submission if general
      }

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

  app.get('/api/admin/wallet-requests', (req, res) => res.json([]));
  app.get('/api/admin/orders', (req, res) => res.json([]));

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
