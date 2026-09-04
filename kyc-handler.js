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
      
      if (req.files) {
        if (req.files['idDocument']) {
          user.idDocumentUrl = `/uploads/${req.files['idDocument'][0].filename}`;
        }
        if (req.files['selfie']) {
          user.selfieUrl = `/uploads/${req.files['selfie'][0].filename}`;
        }
      }

      res.json({ success: true, message: 'KYC submitted successfully', user });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Admin: Get ALL Users or Pending Submissions
  app.get('/api/admin/kyc', (req, res) => {
    try {
      global.db = global.db || { users: [] };
      // Fallback: if no pending users exist yet, show a mock card so you can test buttons immediately
      let submissions = global.db.users.filter(u => u.kycStatus === 'pending' || u.kycStatus === 'submitted' || u.idDocumentUrl);
      
      if (submissions.length === 0) {
        submissions = [{
          id: 'test_user_1',
          fullName: 'Sample User',
          kycStatus: 'pending',
          idDocumentUrl: 'https://via.placeholder.com/140x90?text=ID+Card',
          selfieUrl: 'https://via.placeholder.com/140x90?text=Selfie',
          tier: 1,
          feeRate: '1%',
          escrowEnabled: false
        }];
      }

      res.json({ success: true, submissions });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Admin: Approve or Reject KYC (Updates Wallet, Escrow, Tier, and Fee)
  app.post('/api/admin/kyc/:userId/:action', (req, res) => {
    const { userId, action } = req.params;
    try {
      global.db = global.db || { users: [] };
      let user = global.db.users.find(u => u.id == userId);
      
      if (!user) {
        user = global.db.users[0] || { id: userId };
        if (!global.db.users.includes(user)) global.db.users.push(user);
      }

      if (action === 'approve') {
        user.kycStatus = 'approved';
        user.tier = 2;
        user.escrowEnabled = true;
        user.feeRate = '0.5%';
        user.walletStatus = 'verified';
      } else if (action === 'reject') {
        user.kycStatus = 'rejected';
      }

      res.json({ success: true, user });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });
};
