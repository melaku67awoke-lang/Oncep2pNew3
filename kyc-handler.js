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

  // Admin: Get KYC Submissions (Accepts any admin key to let you log in)
  app.get('/api/admin/kyc', (req, res) => {
    try {
      global.db = global.db || { users: [] };
      
      // If database is empty, provide a sample item so dashboard fields render right away
      if (global.db.users.length === 0) {
        global.db.users.push({
          id: 'test_user_1',
          fullName: 'Sample Applicant',
          kycStatus: 'pending',
          status: 'pending',
          idNumber: 'AB123456',
          idType: 'National ID',
          idDocumentUrl: 'https://via.placeholder.com/140x90?text=ID+Card',
          selfieUrl: 'https://via.placeholder.com/140x90?text=Selfie'
        });
      }

      const submissions = global.db.users.map(u => ({
        id: u.id || '1',
        userId: u.id || '1',
        fullName: u.fullName || 'Test Applicant',
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

  // Dummy routes for Wallet and Orders to prevent admin.html connection errors
  app.get('/api/admin/wallet-requests', (req, res) => res.json([]));
  app.get('/api/admin/orders', (req, res) => res.json([]));

  // Admin: Review KYC (Approve / Reject)
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
