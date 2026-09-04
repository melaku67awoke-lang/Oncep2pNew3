const multer = require('multer');
const path = require('path');

// Shared memory store across the app lifecycle
global.db = global.db || { users: [], submissions: [] };

module.exports = function(app) {
  const kycStorage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, path.join(__dirname, 'public', 'uploads'));
    },
    filename: (req, file, cb) => {
      cb(null, Date.now() + '-' + file.originalname);
    }
  });
  const uploadKyc = multer({ storage: kycStorage });

  app.use('/uploads', require('express').static(path.join(__dirname, 'public', 'uploads')));

  // User KYC Submission
  app.post('/api/kyc/submit', uploadKyc.fields([{ name: 'idDocument', maxCount: 1 }, { name: 'selfie', maxCount: 1 }]), (req, res) => {
    try {
      const userId = req.body.userId || 'user_persistent_1';
      
      let user = global.db.users.find(u => u.id == userId);
      if (!user) {
        user = { id: userId, tier: 1 };
        global.db.users.push(user);
      }

      user.fullName = req.body.fullName || req.body.name || 'Verified Applicant';
      user.kycStatus = 'pending';
      user.status = 'pending';
      user.idNumber = req.body.idNumber || '123456';
      user.idType = req.body.idType || 'ID Card';
      
      if (req.files) {
        if (req.files['idDocument']) {
          user.idDocumentUrl = `/uploads/${req.files['idDocument'][0].filename}`;
          user.idDocument = user.idDocumentUrl;
        }
        if (req.files['selfie']) {
          user.selfieUrl = `/uploads/${req.files['selfie'][0].filename}`;
          user.selfie = user.selfieUrl;
        }
      }

      res.json({ success: true, message: 'KYC submitted successfully', user });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Check user status endpoint so frontend knows if user is pending or approved when reopening
  app.get('/api/kyc/status/:userId', (req, res) => {
    const user = global.db.users.find(u => u.id == req.params.userId);
    if (!user) return res.json({ kycStatus: 'none' });
    res.json(user);
  });

  // Admin Get Submissions
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

  // Admin Review (Approve/Reject)
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
