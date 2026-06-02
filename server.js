const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json());

// ── USER SCHEMA ──
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  googleId: { type: String },
  balance: { type: Number, default: 10000 },
  verified: { type: Boolean, default: false },
  banned: { type: Boolean, default: false }
});
const User = mongoose.model('User', UserSchema);

// ── CO-ADMIN SCHEMA (NEW) ──
const CoAdminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const CoAdmin = mongoose.model('CoAdmin', CoAdminSchema);

const OtpSchema = new mongoose.Schema({
  email: String,
  otp: String,
  createdAt: { type: Date, default: Date.now, expires: 60 }
});
const Otp = mongoose.model('Otp', OtpSchema);

async function sendOTP(email, otp) {
  await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': process.env.BREVO_API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      sender: { name: 'MuniyaX', email: 'ekarthi407@gmail.com' },
      to: [{ email }],
      subject: 'MuniyaX OTP Verification',
      htmlContent: `<h2>Your OTP: <b>${otp}</b></h2><p>Valid for 1 minute.</p>`
    })
  });
}

// ── AUTH ROUTES ──
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await Otp.deleteMany({ email });
    await new Otp({ email, otp }).save();
    await sendOTP(email, o});res.json({ message: 'OTP sent!' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, email, password, otp } = req.body;
    const otpDoc = await Otp.findOne({ email });
    if (!otpDoc || otpDoc.otp !== otp) return res.status(400).json({ message: 'Invalid or expired OTP' });
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: 'Email already exists' });
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashed, verified: true });
    await user.save();
    await Otp.deleteMany({ email });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { username: user.username, balance: user.balance, avatar: '🎮' } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});o

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });
    if (user.banned) return res.status(403).json({ message: 'Account banned' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: 'Wrong password' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { username: user.username, balance: user.balance, avatar: '🎮' } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ message: 'No credential' });
    const payload = JSON.parse(Buffer.from(credential.split('.')[1], 'base64').toString());
    const { sub: googleId, email, name } = payload;
    if (!googleId || !email) return res.status(400).json({ message: 'Invalid Google data' });
    let user = await User.findOne({ email });
    if (user) {
      if (user.banned) return res.status(403).json({ message: 'Account banned' });
      if (!user.googleId) { user.googleId = googleId; user.verified = true; await user.save(); }
    } else {
      const username = name.replace(/\s+/g, '').toLowerCase() + Math.floor(Math.random() * 1000);
      user = new User({ username, email, googleId, verified: true, balance: 10000 });
      await user.save();
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { username: user.username, balance: user.balance, avatar: '🎮' } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── ADMIN MIDDLEWARE ──
function adminAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ message: 'Not admin' });
    req.admin = decoded;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}

// ── CO-ADMIN MIDDLEWARE (NEW) ──
function coAdminAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'coadmin') return res.status(403).json({ message: 'Not co-admin' });
    req.coAdmin = decoded;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}

// ── ADMIN ROUTES ──
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== process.env.ADMIN_PASSWORD) return res.status(401).json({ message: 'Wrong password' });
  const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1d' });
  res.json({ token });
});

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const bannedUsers = await User.countDocuments({ banned: true });
    const totalBalance = await User.aggregate([{ $group: { _id: null, total: { $sum: '$balance' } } }]);
    res.json({ totalUsers, bannedUsers, totalBalance: totalBalance[0]?.total || 0 });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find({}, 'username email balance verified banned createdAt');
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
  });

app.put('/api/admin/users/:id/ban', adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    user.banned = !user.banned;
    await user.save();
    res.json({ message: user.banned ? 'User banned' : 'User unbanned', banned: user.banned });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/admin/users/:id/balance', adminAuth, async (req, res) => {
  try {
    const { balance } = req.body;
    const user = await User.findByIdAndUpdate(req.params.id, { balance }, { new: true });
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'Balance updated', balance: user.balance });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── ADMIN → CO-ADMIN MANAGE ROUTES (NEW) ──

// Co-Admin list
app.get('/api/admin/coadmins', adminAuth, async (req, res) => {
  try {
    const coadmins = await CoAdmin.find({}, 'username createdAt');
    res.json(coadmins);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Co-Admin add
app.post('/api/admin/coadmin/add', adminAuth, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password required' });
    if (password.length < 6) return res.status(400).json({ message: 'Password must be 6+ characters' });
    const exists = await CoAdmin.findOne({ username });
    if (exists) return res.status(400).json({ message: 'Username already exists' });
    const hashed = await bcrypt.hash(password, 10);
    const coadmin = new CoAdmin({ username, password: hashed });
    await coadmin.save();
    res.json({ message: 'Co-Admin created!', username: coadmin.username });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Co-Admin delete
app.delete('/api/admin/coadmin/:id', adminAuth, async (req, res) => {
  try {
    await CoAdmin.findByIdAndDelete(req.params.id);
    res.json({ message: 'Co-Admin deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── CO-ADMIN ROUTES (NEW) ──

// Co-Admin login
app.post('/api/coadmin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const coadmin = await CoAdmin.findOne({ username });
    if (!coadmin) return res.status(400).json({ message: 'Invalid username or password' });
    const match = await bcrypt.compare(password, coadmin.password);
    if (!match) return res.status(400).json({ message: 'Invalid username or password' });
    const token = jwt.sign({ role: 'coadmin', id: coadmin._id, username: coadmin.username }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, username: coadmin.username });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Co-Admin stats
app.get('/api/coadmin/stats', coAdminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const bannedUsers = await User.countDocuments({ banned: true });
    res.json({ totalUsers, bannedUsers });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Co-Admin get users
app.get('/api/coadmin/users', coAdminAuth, async (req, res) => {
  try {
    const users = await User.find({}, 'username email balance banned');
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Co-Admin balance edit
app.put('/api/coadmin/users/:id/balance', coAdminAuth, async (req, res) => {
  try {
    const { balance } = req.body;
    const user = await User.findByIdAndUpdate(req.params.id, { balance }, { new: true });
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'Balance updated', balance: user.balance });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Co-Admin ban/unban
app.put('/api/coadmin/users/:id/ban', coAdminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    user.banned = !user.banned;
    await user.save();
    res.json({ message: user.banned ? 'User banned' : 'User unbanned', banned: user.banned });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── USER ROUTES ──
function authUser(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}

app.get('/api/user/me', authUser, async (req, res) => {
  try {
    const user = await User.findById(req.userId, 'username email balance');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ username: user.username, email: user.email, balance: user.balance });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
// ── DEPOSIT SCHEMA ──
const DepositSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  userName: String,
  userEmail: String,
  amount: Number,
  utr: String,
  method: { type: String, default: 'UPI' },
  status: { type: String, default: 'pending' }
}, { timestamps: true });
const Deposit = mongoose.model('Deposit', DepositSchema);

// ── WITHDRAWAL SCHEMA ──
const WithdrawalSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  userName: String,
  userEmail: String,
  amount: Number,
  upiId: String,
  status: { type: String, default: 'pending' }
}, { timestamps: true });
const Withdrawal = mongoose.model('Withdrawal', WithdrawalSchema);

// ── ADMIN MIDDLEWARE ──
const adminAuth = (req, res, next) => {
  if (req.headers['x-admin-token'] !== process.env.ADMIN_TOKEN)
    return res.status(403).json({ message: 'Admin access denied' });
  next();
};

// ── USER: Submit Deposit ──
app.post('/api/user/deposit', authUser, async (req, res) => {
  try {
    const { amount, utr, method } = req.body;
    if (!amount || amount < 100) return res.status(400).json({ message: 'Minimum ₹100' });
    if (!utr) return res.status(400).json({ message: 'UTR required' });
    const user = await User.findById(req.userId);
    const deposit = await Deposit.create({
      userId: user._id, userName: user.username,
      userEmail: user.email, amount, utr,
      method: method || 'UPI', status: 'pending'
    });
    res.json({ message: 'Deposit submitted! Pending admin approval.', deposit });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

// ── USER: Submit Withdrawal ──
app.post('/api/user/withdraw', authUser, async (req, res) => {
  try {
    const { amount, upiId } = req.body;
    if (!amount || amount < 100) return res.status(400).json({ message: 'Minimum ₹100' });
    const user = await User.findById(req.userId);
    if (user.balance < amount) return res.status(400).json({ message: 'Insufficient balance' });
    const wd = await Withdrawal.create({
      userId: user._id, userName: user.username,
      userEmail: user.email, amount, upiId, status: 'pending'
    });
    res.json({ message: 'Withdrawal submitted! Pending admin approval.', withdrawal: wd });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

// ── ADMIN: Get all users ──
app.get('/api/admin/users', adminAuth, async (req, res) => {
  const users = await User.find().select('-password').sort({ createdAt: -1 });
  res.json({ data: users });
});

// ── ADMIN: Get all deposits ──
app.get('/api/admin/deposits', adminAuth, async (req, res) => {
  const deps = await Deposit.find().sort({ createdAt: -1 });
  res.json({ data: deps });
});

// ── ADMIN: Approve deposit ──
app.post('/api/admin/deposits/:id/approve', adminAuth, async (req, res) => {
  try {
    const dep = await Deposit.findById(req.params.id);
    if (!dep || dep.status !== 'pending') return res.status(400).json({ message: 'Already processed' });
    dep.status = 'approved';
    await dep.save();
    await User.findByIdAndUpdate(dep.userId, { $inc: { balance: dep.amount } });
    res.json({ message: `✅ ₹${dep.amount} approved!` });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

// ── ADMIN: Reject deposit ──
app.post('/api/admin/deposits/:id/reject', adminAuth, async (req, res) => {
  try {
    const dep = await Deposit.findById(req.params.id);
    if (!dep || dep.status !== 'pending') return res.status(400).json({ message: 'Already processed' });
    dep.status = 'rejected';
    await dep.save();
    res.json({ message: 'Deposit rejected' });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

// ── ADMIN: Get all withdrawals ──
app.get('/api/admin/withdrawals', adminAuth, async (req, res) => {
  const wds = await Withdrawal.find().sort({ createdAt: -1 });
  const withBal = await Promise.all(wds.map(async w => {
    const u = await User.findById(w.userId).select('balance');
    return { ...w.toObject(), userBalance: u?.balance || 0 };
  }));
  res.json({ data: withBal });
});

// ── ADMIN: Approve withdrawal ──
app.post('/api/admin/withdrawals/:id/approve', adminAuth, async (req, res) => {
  try {
    const wd = await Withdrawal.findById(req.params.id);
    if (!wd || wd.status !== 'pending') return res.status(400).json({ message: 'Already processed' });
    const user = await User.findById(wd.userId);
    if (!user || user.balance < wd.amount) return res.status(400).json({ message: 'Insufficient balance' });
    user.balance -= wd.amount;
    await user.save();
    wd.status = 'approved';
    await wd.save();
    res.json({ message: `✅ ₹${wd.amount} withdrawal approved!` });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

// ── ADMIN: Reject withdrawal ──
app.post('/api/admin/withdrawals/:id/reject', adminAuth, async (req, res) => {
  try {
    const wd = await Withdrawal.findById(req.params.id);
    if (!wd || wd.status !== 'pending') return res.status(400).json({ message: 'Already processed' });
    wd.status = 'rejected';
    await wd.save();
    res.json({ message: 'Withdrawal rejected' });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

// ── ADMIN: Edit user balance ──
app.post('/api/admin/users/:id/balance', adminAuth, async (req, res) => {
  try {
    const { balance } = req.body;
    const user = await User.findByIdAndUpdate(req.params.id, { balance }, { new: true }).select('-password');
    res.json({ message: 'Balance updated', user });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

// ── ADMIN: Ban/Unban user ──
app.post('/api/admin/users/:id/ban', adminAuth, async (req, res) => {
  try {
    const { banned } = req.body;
    const user = await User.findByIdAndUpdate(req.params.id, { banned }, { new: true }).select('-password');
    res.json({ message: banned ? 'User banned' : 'User unbanned', user });
  } catch(e) { res.status(500).json({ message: e.message }); }
});
app.get('/', (req, res) => res.json({ message: 'MuniyaX Backend Running!' }));

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB Connected!'))
  .catch(err => console.log(err));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
