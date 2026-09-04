const multer = require('multer');
const path = require('path');

module.exports = function(app) {
  // Configure Multer for ID Document and Selfie Uploads
  const kycStorage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, path.join(__dirname, 'public', 'uploads'));
    },
    filename: (req, file, cb) => {
      cb(null, Date.now() + '-' + file.originalname);
    }
  });
  const uploadKyc = multer({ storage: kycStorage });

  // Serve Uploads Statically So Images Render in Admin Dashboard
  app.use('/uploads', require('express').static(path.join(__dirname, 'public', 'uploads')));

  // User KYC Submission Endpoint
  app.post('/api/kyc/submit', uploadKyc.fields([{ name: 'idDocument', maxCount: 1 }, { name: 'selfie', maxCount: 1 }]), (req, res) => {
    try {
      global.db = global.db || { users: [] };
      const userId = req.body.userId || 'user_' + Date.now();
      
      let user = global.db.users.find(u => u.id == userId || u.kycStatus === 'pending');
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

  // Admin: Get KYC Submissions
  app.get('/api/admin/kyc', (req, res) => {
    try {
      global.db = global.db || { users: [] };
      
      // Map users to match admin.html expectations cleanly
      const submissions = global.db.users.map(u => ({
        id: u.id || '1',
        userId: u.id || '1',
        fullName: u.fullName || 'Test Applicant',
        status: u.kycStatus || u.status || 'pending',
        telegramId: u.telegramId || 'N/A',
        idNumber: u.idNumber || '123456',
        idType: u.idType || 'ID Card',
        idDocument: u.idDocumentUrl || u.idDocument || '/uploads/id-placeholder.png',
        selfie: u.selfieUrl || u.selfie || '/uploads/selfie-placeholder.png',
        reason: u.reason || ''
      }));

      res.json(submissions);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Admin: Review KYC (Approve / Reject) matching admin.html endpoint
  app.post('/api/admin/kyc/:id/review', (req, res) => {
    const { id } = req.params;
    const { status, reason } = req.body;
    
    try {
      global.db = global.db || { users: [] };
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
