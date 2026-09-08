const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const kycHandler = require('./kyc-handler');

const app = express();
const PORT = process.env.PORT || 3000;

// Enable CORS and JSON parsing
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

// ==========================================
// PERMANENT BACKEND STORAGE FOR ADS (BUG FIX)
// ==========================================
const ADS_STORAGE_FILE = path.join(__dirname, 'data', 'ads.json');
const DATA_DIR = path.join(__dirname, 'data');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// In-memory cache synced with permanent storage
let ads = [];

/**
 * Load ads permanently from backend storage on startup.
 */
function loadAdsFromStorage() {
  try {
    if (fs.existsSync(ADS_STORAGE_FILE)) {
      const raw = fs.readFileSync(ADS_STORAGE_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        console.log(`[Storage] Loaded ${parsed.length} ads permanently from ${ADS_STORAGE_FILE}`);
        return parsed;
      }
    }
  } catch (err) {
    console.error('[Storage Error] Failed to read ads from permanent backend storage:', err);
  }

  // Fallback defaults if storage does not exist yet
  const defaultAds = [
    {
      id: "ad_101",
      userId: "1001",
      username: "CryptoMaster_Pro",
      type: "SELL",
      crypto: "USDT",
      fiat: "USD",
      price: 1.002,
      amount: 5400,
      available: 5400,
      minLimit: 50,
      maxLimit: 2000,
      paymentMethods: ["Bank Transfer", "Zelle", "Revolut"],
      paymentDetails: "Bank details provided in escrow chat. Fast release guaranteed.",
      terms: "Fast release! Please upload payment receipt. No third party payments allowed.",
      status: "active",
      tradesCount: 384,
      completionRate: 99.6,
      createdAt: "2026-09-01T10:00:00.000Z"
    },
    {
      id: "ad_102",
      userId: "1002",
      username: "TonWhale_Fast",
      type: "SELL",
      crypto: "TON",
      fiat: "USD",
      price: 5.45,
      amount: 1250,
      available: 1250,
      minLimit: 25,
      maxLimit: 1500,
      paymentMethods: ["Telegram Pay", "Bank Transfer", "Wise"],
      paymentDetails: "Instant TON escrow release after payment confirmation.",
      terms: "Online 24/7. Verified traders only. Release within 5 minutes.",
      status: "active",
      tradesCount: 219,
      completionRate: 99.1,
      createdAt: "2026-09-02T12:30:00.000Z"
    },
    {
      id: "ad_103",
      userId: "1003",
      username: "GlobalTrader_USDT",
      type: "BUY",
      crypto: "USDT",
      fiat: "USD",
      price: 0.998,
      amount: 8000,
      available: 8000,
      minLimit: 100,
      maxLimit: 3000,
      paymentMethods: ["Bank Transfer", "Wise", "PayPal"],
      paymentDetails: "Instant payment from verified personal account.",
      terms: "I pay fast. Please do not mark paid before actual transfer.",
      status: "active",
      tradesCount: 512,
      completionRate: 100.0,
      createdAt: "2026-09-03T15:45:00.000Z"
    }
  ];

  saveAdsToStorage(defaultAds);
  return defaultAds;
}

/**
 * Save ads permanently to backend storage.
 * Ensures ads survive Telegram close/reopen and server restarts.
 */
function saveAdsToStorage(adsList) {
  try {
    const tempFile = `${ADS_STORAGE_FILE}.tmp.${Date.now()}`;
    fs.writeFileSync(tempFile, JSON.stringify(adsList, null, 2), 'utf8');
    fs.renameSync(tempFile, ADS_STORAGE_FILE);
    console.log(`[Storage] Saved ${adsList.length} ads permanently to storage.`);
    return true;
  } catch (err) {
    console.error('[Storage Error] Failed to write ads to permanent backend storage:', err);
    try {
      fs.writeFileSync(ADS_STORAGE_FILE, JSON.stringify(adsList, null, 2), 'utf8');
      return true;
    } catch (fallbackErr) {
      console.error('[Storage Fatal] Fallback write also failed:', fallbackErr);
      return false;
    }
  }
}

// Initialize and load ads on startup
ads = loadAdsFromStorage();

// ==========================================
// P2P ADS API ROUTES
// ==========================================

/**
 * GET /api/ads
 * Load all published ads (visible to all users).
 * Optional filters: type (BUY/SELL), crypto, fiat, userId.
 */
app.get('/api/ads', (req, res) => {
  const { type, crypto, fiat, userId, status } = req.query;

  let filtered = [...ads];

  // By default, only return active ads unless specifically querying for user's own ads or admin
  if (status) {
    filtered = filtered.filter(a => a.status === status);
  } else if (!userId) {
    filtered = filtered.filter(a => a.status === 'active');
  }

  if (type) {
    filtered = filtered.filter(a => a.type.toUpperCase() === type.toUpperCase());
  }

  if (crypto) {
    filtered = filtered.filter(a => a.crypto.toUpperCase() === crypto.toUpperCase());
  }

  if (fiat) {
    filtered = filtered.filter(a => a.fiat.toUpperCase() === fiat.toUpperCase());
  }

  if (userId) {
    filtered = filtered.filter(a => String(a.userId) === String(userId));
  }

  // Sort by latest first
  filtered.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  res.json({
    success: true,
    total: filtered.length,
    ads: filtered
  });
});

/**
 * GET /api/my-ads
 * Load ads published by a specific user (My Ads view).
 */
app.get('/api/my-ads', (req, res) => {
  const { userId } = req.query;
  if (!userId) {
    return res.status(400).json({ success: false, error: 'userId query parameter is required' });
  }

  const userAds = ads.filter(a => String(a.userId) === String(userId) && a.status !== 'deleted');
  userAds.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  res.json({
    success: true,
    total: userAds.length,
    ads: userAds
  });
});

/**
 * POST /api/ads
 * Publish a new Buy/Sell Ad.
 * Permanently stores to backend storage (data/ads.json).
 */
app.post('/api/ads', (req, res) => {
  try {
    const {
      userId,
      username,
      type, // 'BUY' or 'SELL'
      crypto, // 'USDT', 'TON', 'BTC', etc.
      fiat, // 'USD', 'EUR', 'ETB', etc.
      price,
      amount,
      minLimit,
      maxLimit,
      paymentMethods,
      paymentDetails,
      terms
    } = req.body;

    if (!userId || !type || !crypto || !fiat || !price || !amount) {
      return res.status(400).json({
        success: false,
        error: 'Missing required ad parameters (userId, type, crypto, fiat, price, amount)'
      });
    }

    const newAd = {
      id: 'ad_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
      userId: String(userId),
      username: username || ('user_' + String(userId).slice(-4)),
      type: type.toUpperCase(),
      crypto: crypto.toUpperCase(),
      fiat: fiat.toUpperCase(),
      price: parseFloat(price),
      amount: parseFloat(amount),
      available: parseFloat(amount),
      minLimit: minLimit ? parseFloat(minLimit) : 10,
      maxLimit: maxLimit ? parseFloat(maxLimit) : parseFloat(amount) * parseFloat(price),
      paymentMethods: Array.isArray(paymentMethods) ? paymentMethods : (paymentMethods ? [paymentMethods] : ['Bank Transfer']),
      paymentDetails: paymentDetails || '',
      terms: terms || '',
      status: 'active',
      tradesCount: 0,
      completionRate: 100.0,
      createdAt: new Date().toISOString()
    };

    // Add to in-memory list
    ads.unshift(newAd);

    // Persist permanently to backend storage immediately
    saveAdsToStorage(ads);

    console.log(`[Ad Published] New ${newAd.type} ad ${newAd.id} by @${newAd.username} permanently stored.`);

    return res.status(201).json({
      success: true,
      message: 'Ad published and saved permanently to backend storage',
      ad: newAd
    });
  } catch (error) {
    console.error('Error publishing ad:', error);
    return res.status(500).json({ success: false, error: 'Internal server error while publishing ad' });
  }
});

/**
 * PUT /api/ads/:id
 * Update an ad (toggle status active/paused or update limits/price).
 */
app.put('/api/ads/:id', (req, res) => {
  const { id } = req.params;
  const { status, price, minLimit, maxLimit, available } = req.body;

  const adIndex = ads.findIndex(a => a.id === id);
  if (adIndex === -1) {
    return res.status(404).json({ success: false, error: 'Ad not found' });
  }

  if (status) ads[adIndex].status = status;
  if (price !== undefined) ads[adIndex].price = parseFloat(price);
  if (minLimit !== undefined) ads[adIndex].minLimit = parseFloat(minLimit);
  if (maxLimit !== undefined) ads[adIndex].maxLimit = parseFloat(maxLimit);
  if (available !== undefined) ads[adIndex].available = parseFloat(available);
  ads[adIndex].updatedAt = new Date().toISOString();

  // Save changes permanently
  saveAdsToStorage(ads);

  res.json({
    success: true,
    message: 'Ad updated and persisted',
    ad: ads[adIndex]
  });
});

/**
 * DELETE /api/ads/:id
 * Delete an ad permanently from storage.
 */
app.delete('/api/ads/:id', (req, res) => {
  const { id } = req.params;
  const initialLength = ads.length;
  ads = ads.filter(a => a.id !== id);

  if (ads.length === initialLength) {
    return res.status(404).json({ success: false, error: 'Ad not found' });
  }

  // Save changes permanently
  saveAdsToStorage(ads);

  res.json({
    success: true,
    message: 'Ad removed from permanent storage'
  });
});

// ==========================================
// WALLET & ESCROW TRADES API ROUTES
// ==========================================
const WALLET_FILE = path.join(DATA_DIR, 'wallets.json');
const TRADES_FILE = path.join(DATA_DIR, 'trades.json');

function loadWallets() {
  try {
    if (fs.existsSync(WALLET_FILE)) return JSON.parse(fs.readFileSync(WALLET_FILE, 'utf8'));
  } catch (e) {}
  return {};
}

function saveWallets(data) {
  try {
    fs.writeFileSync(WALLET_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {}
}

function loadTrades() {
  try {
    if (fs.existsSync(TRADES_FILE)) return JSON.parse(fs.readFileSync(TRADES_FILE, 'utf8'));
  } catch (e) {}
  return [];
}

function saveTrades(data) {
  try {
    fs.writeFileSync(TRADES_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {}
}

let userWallets = loadWallets();
let trades = loadTrades();

app.get('/api/wallet/:userId', (req, res) => {
  const { userId } = req.params;
  if (!userWallets[userId]) {
    // Initial welcome balance for new users
    userWallets[userId] = {
      USDT: 500.00,
      TON: 50.00,
      BTC: 0.025,
      ETH: 0.15
    };
    saveWallets(userWallets);
  }
  res.json({ success: true, balances: userWallets[userId] });
});

app.post('/api/wallet/deposit', (req, res) => {
  const { userId, asset, amount } = req.body;
  if (!userId || !asset || !amount) return res.status(400).json({ success: false, error: 'Missing fields' });

  if (!userWallets[userId]) userWallets[userId] = { USDT: 0, TON: 0, BTC: 0, ETH: 0 };
  userWallets[userId][asset] = (userWallets[userId][asset] || 0) + parseFloat(amount);
  saveWallets(userWallets);

  res.json({ success: true, message: 'Deposit successful', balances: userWallets[userId] });
});

app.post('/api/trades', (req, res) => {
  const { adId, buyerId, sellerId, crypto, fiat, cryptoAmount, fiatAmount, paymentMethod } = req.body;
  const newTrade = {
    id: 'trade_' + Date.now(),
    adId,
    buyerId,
    sellerId,
    crypto,
    fiat,
    cryptoAmount: parseFloat(cryptoAmount),
    fiatAmount: parseFloat(fiatAmount),
    paymentMethod,
    status: 'ESCROW_LOCKED',
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString()
  };

  trades.unshift(newTrade);
  saveTrades(trades);

  res.status(201).json({ success: true, trade: newTrade });
});

app.get('/api/trades/:userId', (req, res) => {
  const { userId } = req.params;
  const userTrades = trades.filter(t => String(t.buyerId) === String(userId) || String(t.sellerId) === String(userId));
  res.json({ success: true, trades: userTrades });
});

app.put('/api/trades/:id/release', (req, res) => {
  const { id } = req.params;
  const trade = trades.find(t => t.id === id);
  if (!trade) return res.status(404).json({ success: false, error: 'Trade not found' });

  trade.status = 'COMPLETED';
  trade.completedAt = new Date().toISOString();
  saveTrades(trades);

  res.json({ success: true, message: 'Escrow released successfully', trade });
});

// ==========================================
// KYC API ROUTES (Handled by kyc-handler)
// ==========================================
app.post('/api/kyc/submit', kycHandler.upload.fields([{ name: 'document', maxCount: 1 }, { name: 'selfie', maxCount: 1 }]), kycHandler.submitKYC);
app.get('/api/kyc/status/:userId', kycHandler.getKYCStatus);
app.get('/api/kyc/all', kycHandler.getAllKYC);
app.post('/api/kyc/review', kycHandler.reviewKYC);

// ==========================================
// ZIP DOWNLOAD ROUTE
// ==========================================
app.get('/download/OnceP2P_V68.zip', (req, res) => {
  const zipPath = path.join(__dirname, '..', 'OnceP2P_V68.zip');
  const localZip = path.join(__dirname, 'OnceP2P_V68.zip');
  
  const targetZip = fs.existsSync(zipPath) ? zipPath : (fs.existsSync(localZip) ? localZip : null);

  if (targetZip) {
    res.download(targetZip, 'OnceP2P_V68.zip');
  } else {
    res.status(404).send('ZIP file not generated yet. Please run zip generation.');
  }
});

// Fallback to index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`====================================================`);
  console.log(`OnceP2P V68 Server running on http://0.0.0.0:${PORT}`);
  console.log(`Permanent backend storage enabled: ${ADS_STORAGE_FILE}`);
  console.log(`====================================================`);
});
