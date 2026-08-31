const express = require('express');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || 'change-me-admin-key';
const DATA = path.join(__dirname, 'data');
const UPLOADS = path.join(__dirname, 'uploads');
for (const d of [DATA, UPLOADS]) fs.mkdirSync(d, { recursive: true });

const files = { users: 'users.json', kyc: 'kyc.json', wallets: 'wallets.json', transactions: 'transactions.json', listings: 'listings.json', orders: 'orders.json', sessions:'sessions.json', messages:'messages.json', notifications:'notifications.json' };
function read(name) { const p = path.join(DATA, files[name]); if (!fs.existsSync(p)) fs.writeFileSync(p, '[]'); return JSON.parse(fs.readFileSync(p, 'utf8')); }
function write(name, value) { fs.writeFileSync(path.join(DATA, files[name]), JSON.stringify(value, null, 2)); }
function id(prefix) { return prefix + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }
function tokenFrom(req){ const h=String(req.header('authorization')||''); return h.startsWith('Bearer ')?h.slice(7).trim():''; }
function userId(req) { const t=tokenFrom(req); if(t){ const s=read('sessions').find(x=>x.token===t && new Date(x.expiresAt)>new Date()); return s?String(s.userId):''; } return ''; }
function requireUser(req, res, next) { if (!userId(req)) return res.status(401).json({ error: 'Please log in' }); next(); }
function addNotification(uid,type,title,body,orderId=''){ const a=read('notifications'); a.push({id:id('ntf'),userId:uid,type,title,body,orderId,read:false,createdAt:new Date().toISOString()}); write('notifications',a); }
function hashPassword(password){ const salt=crypto.randomBytes(16).toString('hex'); const hash=crypto.scryptSync(password,salt,64).toString('hex'); return {salt,hash}; }
function verifyPassword(password,salt,hash){ try{return crypto.timingSafeEqual(crypto.scryptSync(password,salt,64),Buffer.from(hash,'hex'));}catch{return false;} }
function requireAdmin(req, res, next) { if (req.header('x-admin-key') !== ADMIN_KEY) return res.status(403).json({ error: 'Admin access denied' }); next(); }
function requireVerified(req, res, next) { const uid=userId(req); const k=read('kyc').find(x=>x.userId===uid); if(!k || k.status!=='approved') return res.status(403).json({error:'KYC approval required'}); next(); }
function expireOrders(){ const os=read('orders'), ws=read('wallets'), ls=read('listings'), ts=read('transactions'); let changed=false; const now=Date.now(); for(const o of os){ if(['paid_escrow','shipped'].includes(o.status) && o.expiresAt && new Date(o.expiresAt).getTime()<=now){ const bw=ws.find(x=>x.userId===o.buyerId); if(bw && Number(bw.heldBalance||0)>=o.amount){ bw.heldBalance=Number((Number(bw.heldBalance||0)-o.amount).toFixed(2)); bw.balance=Number((Number(bw.balance+o.amount)).toFixed(2)); o.status='expired'; o.updatedAt=new Date().toISOString(); ts.push({id:id('tx'),userId:o.buyerId,type:'marketplace_expiry_refund',amount:o.amount,status:'completed',orderId:o.id,createdAt:new Date().toISOString()}); const l=ls.find(x=>x.id===o.listingId); if(l) l.status='active'; addNotification(o.buyerId,'order_update','Trade expired','The trade deadline passed and your escrow was refunded.',o.id); addNotification(o.sellerId,'order_update','Trade expired','The trade deadline passed and the order was cancelled.',o.id); changed=true; } } } if(changed){write('orders',os);write('wallets',ws);write('listings',ls);write('transactions',ts);} }
setInterval(expireOrders, 30000);

app.use(cors()); app.use(express.json({ limit: '1mb' })); app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(UPLOADS));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
  storage: multer.diskStorage({destination: UPLOADS, filename: (req,file,cb) => cb(null, id('doc') + path.extname(file.originalname).toLowerCase())}),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, /image\/(jpeg|png)|application\/pdf/.test(file.mimetype))
});

app.get('/api/health', (req,res)=>res.json({ok:true, app:'Once P2P'}));

// AUTHENTICATION
app.post('/api/auth/register',(req,res)=>{
  const username=String(req.body.username||'').trim().slice(0,40), fullName=String(req.body.fullName||'').trim().slice(0,100), password=String(req.body.password||'');
  if(!username||!fullName||password.length<8) return res.status(400).json({error:'Full name, username and password (8+ characters) are required'});
  const users=read('users'); if(users.some(u=>u.username.toLowerCase()===username.toLowerCase())) return res.status(409).json({error:'Username already exists'});
  const uid='u_'+crypto.randomUUID(); const pw=hashPassword(password); const u={id:id('usr'),userId:uid,username,fullName,passwordHash:pw.hash,passwordSalt:pw.salt,createdAt:new Date().toISOString()}; users.push(u); write('users',users);
  const ws=read('wallets'); ws.push({id:id('wal'),userId:uid,balance:0,heldBalance:0,currency:'ETB'}); write('wallets',ws);
  const token=crypto.randomBytes(32).toString('hex'); const ss=read('sessions'); ss.push({id:id('ses'),token,userId:uid,createdAt:new Date().toISOString(),expiresAt:new Date(Date.now()+30*24*3600*1000).toISOString()}); write('sessions',ss);
  res.status(201).json({token,user:{userId:uid,username,fullName}});
});
app.post('/api/auth/login',(req,res)=>{
  const username=String(req.body.username||'').trim(), password=String(req.body.password||''); const u=read('users').find(x=>x.username.toLowerCase()===username.toLowerCase());
  if(!u||!u.passwordHash||!verifyPassword(password,u.passwordSalt,u.passwordHash)) return res.status(401).json({error:'Invalid username or password'});
  const token=crypto.randomBytes(32).toString('hex'); const ss=read('sessions'); ss.push({id:id('ses'),token,userId:u.userId,createdAt:new Date().toISOString(),expiresAt:new Date(Date.now()+30*24*3600*1000).toISOString()}); write('sessions',ss);
  res.json({token,user:{userId:u.userId,username:u.username,fullName:u.fullName}});
});
app.post('/api/auth/logout',requireUser,(req,res)=>{const t=tokenFrom(req);write('sessions',read('sessions').filter(x=>x.token!==t));res.json({ok:true})});

// USER + KYC
app.post('/api/users',(req,res)=>res.status(410).json({error:'Use /api/auth/register'}));
app.get('/api/me', requireUser, (req,res)=>{
  const uid=userId(req);
  const u=read('users').find(x=>x.userId===uid);
  const k=read('kyc').find(x=>x.userId===uid);
  const w=read('wallets').find(x=>x.userId===uid);
  // Never send identity documents or ID numbers back to the normal user client.
  const safeKyc = k ? { id:k.id, status:k.status, reason:k.reason||'', submittedAt:k.submittedAt, reviewedAt:k.reviewedAt } : {status:'not_submitted'};
  res.json({user:u||null,kyc:safeKyc,wallet:w?{balance:w.balance,heldBalance:Number(w.heldBalance||0),currency:w.currency}:null});
});
app.post('/api/kyc', requireUser, upload.fields([{name:'idDocument',maxCount:1},{name:'selfie',maxCount:1}]), (req,res)=>{
  const uid=userId(req); const { fullName,dob,address,idType,idNumber }=req.body;
  if(!fullName||!dob||!address||!idType||!idNumber) return res.status(400).json({error:'All KYC fields are required'});
  if(!req.files?.idDocument?.[0]||!req.files?.selfie?.[0]) return res.status(400).json({error:'ID document and selfie are required'});
  const all=read('kyc'); const old=all.find(x=>x.userId===uid); if(old && old.status==='approved') return res.status(400).json({error:'KYC already approved'}); if(old){ for(const field of ['idDocument','selfie']){ const oldPath=old[field]; if(oldPath && oldPath.startsWith('/uploads/')){ const fp=path.join(UPLOADS,path.basename(oldPath)); if(fs.existsSync(fp)) fs.unlinkSync(fp); } } }
  const record={id:old?.id||id('kyc'),userId:uid,fullName,dob,address,idType,idNumber,idDocument:'/uploads/'+req.files.idDocument[0].filename,selfie:'/uploads/'+req.files.selfie[0].filename,status:'pending',reason:'',submittedAt:new Date().toISOString(),reviewedAt:null};
  const next=all.filter(x=>x.userId!==uid); next.push(record); write('kyc',next);
  const users=read('users'); const u=users.find(x=>x.userId===uid); if(u){u.fullName=fullName; write('users',users)}
  res.status(201).json(record);
});
app.get('/api/admin/kyc', requireAdmin, (req,res)=>res.json(read('kyc').sort((a,b)=>b.submittedAt.localeCompare(a.submittedAt))));
app.post('/api/admin/kyc/:id/review', requireAdmin, (req,res)=>{
  const {status,reason=''}=req.body; if(!['approved','rejected'].includes(status)) return res.status(400).json({error:'status must be approved or rejected'});
  const all=read('kyc'); const k=all.find(x=>x.id===req.params.id); if(!k)return res.status(404).json({error:'KYC not found'}); k.status=status;k.reason=reason;k.reviewedAt=new Date().toISOString();write('kyc',all);res.json(k);
});

// WALLET - demo ledger. In production use a database + authenticated payment provider/webhook.
app.get('/api/wallet', requireUser, requireVerified, (req,res)=>{ const w=read('wallets').find(x=>x.userId===userId(req)); res.json(w||{balance:0,heldBalance:0,currency:'ETB'}); });
app.get('/api/wallet/transactions', requireUser, requireVerified, (req,res)=>res.json(read('transactions').filter(x=>x.userId===userId(req)).reverse()));
function validAmount(value){ const n=Number(value); return Number.isFinite(n) && n>0 && n<=100000000 && Math.round(n*100)===n*100; }
function ensureWallet(uid){ const ws=read('wallets'); let w=ws.find(x=>x.userId===uid); if(!w){w={id:id('wal'),userId:uid,balance:0,heldBalance:0,currency:'ETB'};ws.push(w);write('wallets',ws)} return w; }
app.post('/api/wallet/demo-credit', requireAdmin, (req,res)=>{
  const {userId:uid,amount,note='Demo credit'}=req.body; const n=Number(amount); if(!uid||!validAmount(n))return res.status(400).json({error:'Valid amount with up to 2 decimals is required'});
  const ws=read('wallets');let w=ws.find(x=>x.userId===String(uid));if(!w){w={id:id('wal'),userId:String(uid),balance:0,heldBalance:0,currency:'ETB'};ws.push(w)}w.balance=Number((w.balance+n).toFixed(2));write('wallets',ws);
  const tx={id:id('tx'),userId:String(uid),type:'admin_credit',amount:n,status:'completed',note,createdAt:new Date().toISOString()};const ts=read('transactions');ts.push(tx);write('transactions',ts);res.json({wallet:{balance:w.balance,currency:w.currency},transaction:tx});
});
app.post('/api/wallet/deposit-request', requireUser, requireVerified, (req,res)=>{
  const n=Number(req.body.amount), method=String(req.body.method||'manual'); if(!validAmount(n))return res.status(400).json({error:'Enter a valid amount with up to 2 decimals'});
  const pending=read('transactions').find(x=>x.userId===userId(req)&&x.type==='deposit'&&x.status==='pending'); if(pending)return res.status(400).json({error:'You already have a pending deposit request'});
  const tx={id:id('tx'),userId:userId(req),type:'deposit',amount:n,status:'pending',method,reference:String(req.body.reference||'').slice(0,100),createdAt:new Date().toISOString()};const ts=read('transactions');ts.push(tx);write('transactions',ts);res.status(201).json(tx);
});
app.post('/api/wallet/withdraw-request', requireUser, requireVerified, (req,res)=>{
  const n=Number(req.body.amount), method=String(req.body.method||'bank'); if(!validAmount(n))return res.status(400).json({error:'Enter a valid amount with up to 2 decimals'});
  const w=read('wallets').find(x=>x.userId===userId(req)); if(!w||w.balance<n)return res.status(400).json({error:'Insufficient wallet balance'});
  const pending=read('transactions').find(x=>x.userId===userId(req)&&x.type==='withdrawal'&&x.status==='pending'); if(pending)return res.status(400).json({error:'You already have a pending withdrawal request'});
  const ts=read('transactions');const tx={id:id('tx'),userId:userId(req),type:'withdrawal',amount:n,status:'pending',method,account:String(req.body.account||'').slice(0,120),createdAt:new Date().toISOString()};ts.push(tx);write('transactions',ts);res.status(201).json(tx);
});
app.get('/api/admin/wallet-requests', requireAdmin, (req,res)=>res.json(read('transactions').filter(x=>['deposit','withdrawal'].includes(x.type)).reverse()));
app.post('/api/admin/wallet-requests/:id/review', requireAdmin, (req,res)=>{
  const {status,reason=''}=req.body;if(!['completed','rejected'].includes(status))return res.status(400).json({error:'status must be completed or rejected'});
  const ts=read('transactions'),tx=ts.find(x=>x.id===req.params.id);if(!tx)return res.status(404).json({error:'Request not found'});if(!['deposit','withdrawal'].includes(tx.type)||tx.status!=='pending')return res.status(400).json({error:'Request is not pending'});
  if(status==='completed'){
    const ws=read('wallets');let w=ws.find(x=>x.userId===tx.userId);if(!w){w={id:id('wal'),userId:tx.userId,balance:0,heldBalance:0,currency:'ETB'};ws.push(w)}
    if(tx.type==='deposit') w.balance=Number((w.balance+tx.amount).toFixed(2));
    else {if(w.balance<tx.amount)return res.status(400).json({error:'User no longer has enough balance'});w.balance=Number((w.balance-tx.amount).toFixed(2));}
    write('wallets',ws);
  }
  tx.status=status;tx.reason=String(reason).slice(0,300);tx.reviewedAt=new Date().toISOString();write('transactions',ts);res.json(tx);
});
app.post('/api/wallet/transfer', requireUser, requireVerified, (req,res)=>{
  const from=userId(req),to=String(req.body.toUserId||''),n=Number(req.body.amount); if(!to||to===from||!validAmount(n))return res.status(400).json({error:'Valid recipient and amount required'});
  const recipientKyc=read('kyc').find(x=>x.userId===to);if(!recipientKyc||recipientKyc.status!=='approved')return res.status(400).json({error:'Recipient must have approved KYC'});const ws=read('wallets');const a=ws.find(x=>x.userId===from),b=ws.find(x=>x.userId===to);if(!a||!b)return res.status(404).json({error:'Sender or recipient wallet not found'});if(a.balance<n)return res.status(400).json({error:'Insufficient balance'});
  a.balance=Number((a.balance-n).toFixed(2));b.balance=Number((b.balance+n).toFixed(2));write('wallets',ws);const ts=read('transactions');const now=new Date().toISOString();ts.push({id:id('tx'),userId:from,type:'transfer_out',amount:n,status:'completed',toUserId:to,createdAt:now},{id:id('tx'),userId:to,type:'transfer_in',amount:n,status:'completed',fromUserId:from,createdAt:now});write('transactions',ts);res.json({ok:true,sender:a,recipient:b});
});

// MARKETPLACE WITH ESCROW
app.get('/api/listings',(req,res)=>{const category=String(req.query.category||'').trim();const q=String(req.query.q||'').trim().toLowerCase();let a=read('listings').filter(x=>x.status==='active');if(category)a=a.filter(x=>x.category===category);if(q)a=a.filter(x=>(x.title+' '+x.description).toLowerCase().includes(q));res.json(a.reverse())});
app.post('/api/listings',requireUser,requireVerified,(req,res)=>{const {title,description,price,category='Other'}=req.body;const n=Number(price);if(!String(title||'').trim()||!String(description||'').trim()||!Number.isFinite(n)||n<=0||Math.round(n*100)!==n*100)return res.status(400).json({error:'Title, description and valid price required'});const l={id:id('lst'),sellerId:userId(req),title:String(title).trim().slice(0,120),description:String(description).trim().slice(0,1000),price:Number(n.toFixed(2)),category:String(category).slice(0,50),status:'active',createdAt:new Date().toISOString()};const a=read('listings');a.push(l);write('listings',a);res.status(201).json(l)});
app.delete('/api/listings/:id',requireUser,requireVerified,(req,res)=>{const a=read('listings'),l=a.find(x=>x.id===req.params.id);if(!l)return res.status(404).json({error:'Listing not found'});if(l.sellerId!==userId(req))return res.status(403).json({error:'Only the seller can remove this listing'});if(l.status!=='active')return res.status(400).json({error:'Listing is no longer active'});l.status='cancelled';write('listings',a);res.json(l)});
app.post('/api/orders',requireUser,requireVerified,(req,res)=>{const buyer=userId(req),{listingId}=req.body;const ls=read('listings'),l=ls.find(x=>x.id===listingId&&x.status==='active');if(!l)return res.status(404).json({error:'Listing not found or already reserved'});if(l.sellerId===buyer)return res.status(400).json({error:'You cannot buy your own listing'});const sellerKyc=read('kyc').find(x=>x.userId===l.sellerId);if(!sellerKyc||sellerKyc.status!=='approved')return res.status(400).json({error:'Seller is not currently KYC verified'});const ws=read('wallets'),bw=ws.find(x=>x.userId===buyer),sw=ws.find(x=>x.userId===l.sellerId);if(!bw||bw.balance<l.price)return res.status(400).json({error:'Insufficient available wallet balance'});if(!sw)return res.status(400).json({error:'Seller wallet not found'});bw.balance=Number((bw.balance-l.price).toFixed(2));bw.heldBalance=Number((Number(bw.heldBalance||0)+l.price).toFixed(2));l.status='reserved';write('wallets',ws);write('listings',ls);const nowIso=new Date().toISOString(); const order={id:id('ord'),listingId,buyerId:buyer,sellerId:l.sellerId,amount:l.price,title:l.title,status:'paid_escrow',createdAt:nowIso,updatedAt:nowIso,shipBy:new Date(Date.now()+48*3600*1000).toISOString(),completeBy:new Date(Date.now()+7*24*3600*1000).toISOString(),expiresAt:new Date(Date.now()+7*24*3600*1000).toISOString(),shippingNote:'',trackingNumber:'',carrier:''};const os=read('orders');os.push(order);write('orders',os);const ts=read('transactions'),now=new Date().toISOString();ts.push({id:id('tx'),userId:buyer,type:'marketplace_escrow_hold',amount:l.price,status:'held',orderId:order.id,createdAt:now});write('transactions',ts);res.status(201).json(order)});
app.get('/api/orders',requireUser,requireVerified,(req,res)=>{const uid=userId(req);res.json(read('orders').filter(x=>x.buyerId===uid||x.sellerId===uid).reverse())});
function getOrder(idv){return read('orders').find(x=>x.id===idv)}
app.post('/api/orders/:id/ship',requireUser,requireVerified,(req,res)=>{const uid=userId(req),os=read('orders'),o=os.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:'Order not found'});if(o.sellerId!==uid)return res.status(403).json({error:'Only the seller can mark an order shipped'});if(o.status!=='paid_escrow')return res.status(400).json({error:'Order is not ready for shipping'});o.status='shipped';o.shippingNote=String(req.body.note||'').slice(0,300);o.trackingNumber=String(req.body.trackingNumber||'').trim().slice(0,100);o.carrier=String(req.body.carrier||'').trim().slice(0,80);o.shippedAt=new Date().toISOString();o.updatedAt=new Date().toISOString();write('orders',os);addNotification(o.buyerId,'order_update','Order shipped','The seller marked your order as shipped.',o.id);res.json(o)});
app.post('/api/orders/:id/deliver',requireUser,requireVerified,(req,res)=>{const uid=userId(req),os=read('orders'),o=os.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:'Order not found'});if(o.sellerId!==uid)return res.status(403).json({error:'Only the seller can mark delivery'});if(o.status!=='shipped')return res.status(400).json({error:'Order must be shipped first'});o.status='delivered';o.deliveredAt=new Date().toISOString();o.updatedAt=new Date().toISOString();write('orders',os);addNotification(o.buyerId,'order_update','Order delivered','The seller marked your order as delivered.',o.id);res.json(o)});
app.post('/api/orders/:id/confirm',requireUser,requireVerified,(req,res)=>{const uid=userId(req),os=read('orders'),o=os.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:'Order not found'});if(o.buyerId!==uid)return res.status(403).json({error:'Only the buyer can confirm receipt'});if(!['shipped','delivered'].includes(o.status))return res.status(400).json({error:'Order is not ready for confirmation'});const ws=read('wallets'),bw=ws.find(x=>x.userId===o.buyerId),sw=ws.find(x=>x.userId===o.sellerId);if(!bw||!sw||Number(bw.heldBalance||0)<o.amount)return res.status(400).json({error:'Escrow funds are unavailable'});bw.heldBalance=Number((Number(bw.heldBalance||0)-o.amount).toFixed(2));sw.balance=Number((sw.balance+o.amount).toFixed(2));o.status='completed';o.updatedAt=new Date().toISOString();write('wallets',ws);write('orders',os);const ts=read('transactions'),now=new Date().toISOString();ts.push({id:id('tx'),userId:o.buyerId,type:'marketplace_escrow_release',amount:o.amount,status:'completed',orderId:o.id,createdAt:now},{id:id('tx'),userId:o.sellerId,type:'marketplace_sale',amount:o.amount,status:'completed',orderId:o.id,createdAt:now});write('transactions',ts);const ls=read('listings'),l=ls.find(x=>x.id===o.listingId);if(l)l.status='sold';write('listings',ls);res.json(o)});
app.post('/api/orders/:id/cancel',requireUser,requireVerified,(req,res)=>{const uid=userId(req),os=read('orders'),o=os.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:'Order not found'});if(![o.buyerId,o.sellerId].includes(uid))return res.status(403).json({error:'Not allowed'});if(!['paid_escrow','shipped'].includes(o.status))return res.status(400).json({error:'Order cannot be cancelled at this stage'});const ws=read('wallets'),bw=ws.find(x=>x.userId===o.buyerId);if(!bw||Number(bw.heldBalance||0)<o.amount)return res.status(400).json({error:'Escrow funds are unavailable'});bw.heldBalance=Number((Number(bw.heldBalance||0)-o.amount).toFixed(2));bw.balance=Number((bw.balance+o.amount).toFixed(2));o.status='cancelled';o.cancelledBy=uid;o.updatedAt=new Date().toISOString();write('wallets',ws);write('orders',os);const ls=read('listings'),l=ls.find(x=>x.id===o.listingId);if(l)l.status='active';write('listings',ls);const ts=read('transactions'),now=new Date().toISOString();ts.push({id:id('tx'),userId:o.buyerId,type:'marketplace_escrow_refund',amount:o.amount,status:'completed',orderId:o.id,createdAt:now});write('transactions',ts);res.json(o)});
app.post('/api/orders/:id/dispute',requireUser,requireVerified,(req,res)=>{const uid=userId(req),os=read('orders'),o=os.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:'Order not found'});if(![o.buyerId,o.sellerId].includes(uid))return res.status(403).json({error:'Not allowed'});if(['completed','cancelled','disputed'].includes(o.status))return res.status(400).json({error:'Order cannot be disputed'});o.status='disputed';o.disputeBy=uid;o.disputeReason=String(req.body.reason||'').slice(0,500);o.updatedAt=new Date().toISOString();write('orders',os);res.json(o)});
app.get('/api/admin/orders',requireAdmin,(req,res)=>res.json(read('orders').reverse()));
app.post('/api/admin/orders/:id/resolve',requireAdmin,(req,res)=>{const {decision,reason=''}=req.body;const os=read('orders'),o=os.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:'Order not found'});if(o.status!=='disputed')return res.status(400).json({error:'Order is not disputed'});if(!['refund_buyer','release_seller'].includes(decision))return res.status(400).json({error:'Decision must be refund_buyer or release_seller'});const ws=read('wallets'),bw=ws.find(x=>x.userId===o.buyerId),sw=ws.find(x=>x.userId===o.sellerId);if(!bw||!sw||Number(bw.heldBalance||0)<o.amount)return res.status(400).json({error:'Escrow funds are unavailable'});bw.heldBalance=Number((Number(bw.heldBalance||0)-o.amount).toFixed(2));if(decision==='refund_buyer'){bw.balance=Number((bw.balance+o.amount).toFixed(2));o.status='refunded'}else{sw.balance=Number((sw.balance+o.amount).toFixed(2));o.status='completed'}o.adminDecision=decision;o.adminReason=String(reason).slice(0,500);o.updatedAt=new Date().toISOString();write('wallets',ws);write('orders',os);const ts=read('transactions'),now=new Date().toISOString();ts.push({id:id('tx'),userId:decision==='refund_buyer'?o.buyerId:o.sellerId,type:decision==='refund_buyer'?'marketplace_dispute_refund':'marketplace_dispute_release',amount:o.amount,status:'completed',orderId:o.id,createdAt:now});write('transactions',ts);const ls=read('listings'),l=ls.find(x=>x.id===o.listingId);if(l)l.status=decision==='refund_buyer'?'active':'sold';write('listings',ls);res.json(o)});

app.get('/api/admin/orders/:id/evidence', requireAdmin, (req,res)=>{ const o=getOrder(req.params.id); if(!o)return res.status(404).json({error:'Order not found'}); res.json((o.evidence||[]).map(e=>({id:e.id,userId:e.userId,path:e.path,createdAt:e.createdAt}))); });
// NOTIFICATIONS + TRADE CHAT/EVIDENCE
app.get('/api/notifications',requireUser,(req,res)=>res.json(read('notifications').filter(x=>x.userId===userId(req)).reverse().slice(0,100)));
app.post('/api/notifications/:id/read',requireUser,(req,res)=>{const a=read('notifications'),n=a.find(x=>x.id===req.params.id&&x.userId===userId(req));if(!n)return res.status(404).json({error:'Notification not found'});n.read=true;write('notifications',a);res.json(n)});
app.get('/api/orders/:id/messages',requireUser,requireVerified,(req,res)=>{const o=getOrder(req.params.id);if(!o||![o.buyerId,o.sellerId].includes(userId(req)))return res.status(404).json({error:'Trade not found'});res.json(read('messages').filter(x=>x.orderId===o.id).map(x=>({id:x.id,fromUserId:x.fromUserId,body:x.body,createdAt:x.createdAt})));});
app.post('/api/orders/:id/messages',requireUser,requireVerified,(req,res)=>{const o=getOrder(req.params.id),uid=userId(req);if(!o||![o.buyerId,o.sellerId].includes(uid))return res.status(404).json({error:'Trade not found'});const body=String(req.body.body||'').trim().slice(0,1000);if(!body)return res.status(400).json({error:'Message is required'});const m={id:id('msg'),orderId:o.id,fromUserId:uid,body,createdAt:new Date().toISOString()};const a=read('messages');a.push(m);write('messages',a);addNotification(uid===o.buyerId?o.sellerId:o.buyerId,'trade_message','New trade message','You received a new message in trade '+o.id,o.id);res.status(201).json(m);});
app.post('/api/orders/:id/evidence',requireUser,requireVerified,upload.single('evidence'),(req,res)=>{const o=getOrder(req.params.id),uid=userId(req);if(!o||![o.buyerId,o.sellerId].includes(uid))return res.status(404).json({error:'Trade not found'});if(!req.file)return res.status(400).json({error:'Evidence file required'});o.evidence=o.evidence||[];o.evidence.push({id:id('ev'),userId:uid,path:'/uploads/'+req.file.filename,createdAt:new Date().toISOString()});const os=read('orders');const idx=os.findIndex(x=>x.id===o.id);os[idx]=o;write('orders',os);res.status(201).json({id:o.evidence.at(-1).id,createdAt:o.evidence.at(-1).createdAt});});

app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`Once P2P running on port ${PORT}`));
