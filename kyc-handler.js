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
  app.use('/uploads', app.get('env') === 'production' 
    ? require('express').static(path.join(__dirname, 'public', 'uploads')) 
    : require('express').static(path.join(__dirname, 'public', 'uploads'))
  );

  // User KYC Submission Endpoint
  app.post('/api/kyc/submit', uploadKyc.fields([{ name: 'idDocument', maxCount: 1 }, { name: 'selfie', maxCount: 1 }]), (req, res) => {
    try {
      const userId = req.body.userId || 1;
      global.db = global.db || { users: [] };
      let user = global.db.users.find(u => u.id == userId);
      
      if (!user) {
        user = { id: userId, tier: 1 };
        global.db.users.push(user);
      }

      user.fullName = req.body.fullName || 'User ' + userId;
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

  // Admin: Get Pending KYC Submissions
  app.get('/api/admin/kyc', (req, res) => {
    try {
      global.db = global.db || { users: [] };
      const submissions = global.db.users.filter(u => u.kycStatus === 'pending' || u.kycStatus === 'submitted');
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
      const user = global.db.users.find(u => u.id == userId);
      
      if (!user) {
        return res.status(404).json({ success: false, error: 'User not found' });
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
