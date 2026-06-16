const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE'], allowedHeaders: ['Content-Type','Authorization','x-admin-token'] }));
app.use(express.json());

// ── USER SCHEMA ──
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  googleId: { type: String },
  balance: { type: Number, default: 0 },
  verified: { type: Boolean, default: false },
  banned: { type: Boolean, default: false }
}, { timestamps: true });
const User = mongoose.model('User', UserSchema);

// ── OTP SCHEMA ──
const OtpSchema = new mongoose.Schema({
  email: String,
  otp: String,
  createdAt: { type: Date, default: Date.now, expires: 60 }
});
const Otp = mongoose.model('Otp', OtpSchema);

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

// ── SEND OTP via Brevo ──
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

// ── MIDDLEWARES ──
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

// Admin auth — uses x-admin-token header (matches admin panel)
function adminAuth(req, res, next) {
  if (req.headers['x-admin-token'] !== process.env.ADMIN_TOKEN)
    return res.status(403).json({ message: 'Admin access denied' });
  next();
}

// ── AUTH ROUTES ──
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await Otp.deleteMany({ email });
    await new Otp({ email, otp }).save();
    await sendOTP(email, otp);
    res.json({ message: 'OTP sent!' });
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
    const user = new User({ username, email, password: hashed, verified: true, balance: 50 });
    await user.save();
    await Otp.deleteMany({ email });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { username: user.username, balance: user.balance, avatar: '🎮' } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

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
      user = new User({ username, email, googleId, verified: true, balance: 50 });
      await user.save();
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { username: user.username, balance: user.balance, avatar: '🎮' } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── USER ROUTES ──
app.get('/api/user/me', authUser, async (req, res) => {
  try {
    const user = await User.findById(req.userId, 'username email balance');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ username: user.username, email: user.email, balance: user.balance });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/user/deposit',}authUser, async (req, res) => {
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

// ── ADMIN ROUTES ──
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json({ data: users });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/admin/deposits', adminAuth, async (req, res) => {
  try {
    const deps = await Deposit.find().sort({ createdAt: -1 });
    res.json({ data: deps });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/admin/withdrawals', adminAuth, async (req, res) => {
  try {
    const wds = await Withdrawal.find().sort({ createdAt: -1 });
    const withBal = await Promise.all(wds.map(async w => {
      const u = await User.findById(w.userId).select('balance');
      return { ...w.toObject(), userBalance: u?.balance || 0 };
    }));
    res.json({ data: withBal });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

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

app.post('/api/admin/deposits/:id/reject', adminAuth, async (req, res) => {
  try {
    const dep = await Deposit.findById(req.params.id);
    if (!dep || dep.status !== 'pending') return res.status(400).json({ message: 'Already processed' });
    dep.status = 'rejected';
    await dep.save();
    res.json({ message: 'Deposit rejected' });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

app.post('/api/admin/withdrawals/:id/approve', adminAuth, async (req, res) => {
  try {
    const wd = await Withdrawal.findById(req.params.id);
    if (!wd || wd.status !== 'pending') return res.status(400).json({ message: 'Already processed' });
    const user = await User.findById(wd.userId);
    if (!user || user.balance < wd.amount) return res.status(400).json({ message: 'Insufficient balance' });
    user.balance -= wd.amount;
    if (user.balance < 0) user.balance = 0;
    await user.save();
    wd.status = 'approved';
    await wd.save();
    res.json({ message: `✅ ₹${wd.amount} withdrawal approved!` });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

app.post('/api/admin/withdrawals/:id/reject', adminAuth, async (req, res) => {
  try {
    const wd = await Withdrawal.findById(req.params.id);
    if (!wd || wd.status !== 'pending') return res.status(400).json({ message: 'Already processed' });
    wd.status = 'rejected';
    await wd.save();
    res.json({ message: 'Withdrawal rejected' });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

app.post('/api/admin/users/:id/balance', adminAuth, async (req, res) => {
  try {
    const { balance } = req.body;
    const user = await User.findByIdAndUpdate(req.params.id, { balance }, { new: true }).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'Balance updated', user });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

app.post('/api/admin/users/:id/ban', adminAuth, async (req, res) => {
  try {
    const { banned } = req.body;
    const user = await User.findByIdAndUpdate(req.params.id, { banned }, { new: true }).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ message: banned ? 'User banned' : 'User unbanned', user });
  } catch(e) { res.status(500).json({ message: e.message }); }
  });
// ── SPORTS PROXY ──
const https = require('https');

const CRIC_API_KEY  = 'b43e3211-5811-4719-bd4b-fc2523fb745d';
const FOOT_API_KEY  = 'efc33b989d414d0aa99a94dd6e19c53a';

// ── Cricket via CricAPI ──
async function fetchCricket(type) {
  return new Promise((resolve) => {
    const path = type === 'live'
      ? '/api/v1/currentMatches?apikey=' + CRIC_API_KEY + '&offset=0'
      : '/api/v1/matches?apikey='        + CRIC_API_KEY + '&offset=0';
    const opts = { hostname: 'api.cricapi.com', path, method: 'GET', headers: { 'Content-Type': 'application/json' } };
    const req = https.request(opts, (r) => {
      let d = '';
      r.on('data', c => d += c);
      r.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.end();
  });
}

// ── Football via Football-Data.org ──
async function fetchFootball(type) {
  return new Promise((resolve) => {
    const today = new Date().toISOString().slice(0,10);
    const tomorrow = new Date(Date.now() + 86400000).toISOString().slice(0,10);
    const path = type === 'live'
      ? '/v4/matches?status=IN_PLAY'
      : '/v4/matches?dateFrom=' + today + '&dateTo=' + tomorrow;
    const opts = {
      hostname: 'api.football-data.org',
      path, method: 'GET',
      headers: { 'X-Auth-Token': FOOT_API_KEY }
    };
    const req = https.request(opts, (r) => {
      let d = '';
      r.on('data', c => d += c);
      r.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.end();
  });
}

// ── Mock data for Basketball / MMA / Rugby ──
function getMockData(sport, type) {
  const now = new Date();
  const fmt = (h, m) => {
    const d = new Date(); d.setHours(h, m, 0);
    return d.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
  };
  const mocks = {
    basketball: {
      live: [
        { id:'b1', league:'NBA · Playoffs', home:'Lakers', away:'Warriors', score:'89', away_score:'94', minute:'Q3 4:32' },
        { id:'b2', league:'NBA · Playoffs', home:'Celtics', away:'Heat',    score:'72', away_score:'68', minute:'Q2 1:15' }
      ],
      upcoming: [
        { id:'b3', league:'NBA · Finals G2', home:'Thunder',  away:'Nuggets', minute: fmt(6,0)  },
        { id:'b4', league:'NBA · Playoffs',  home:'Bucks',    away:'Sixers',  minute: fmt(8,30) }
      ]
    },
    mma: {
      live: [],
      upcoming: [
        { id:'m1', league:'UFC 310 · Main Event', home:'Adesanya', away:'Pereira',  minute: fmt(9,0)  },
        { id:'m2', league:'UFC 310 · Co-Main',    home:'Gaethje',  away:'Holloway', minute: fmt(7,30) }
      ]
    },
    rugby: {
      live: [],
      upcoming: [
        { id:'r1', league:'Rugby World Cup · QF', home:'New Zealand',   away:'South Africa', minute: fmt(16,0) },
        { id:'r2', league:'Six Nations · RD5',    home:'England',       away:'France',       minute: fmt(17,30) }
      ]
    }
  };
  return mocks[sport] ? mocks[sport][type] || [] : [];
}

app.get('/api/sports/:sport', async (req, res) => {
  const sport = req.params.sport;
  const type  = req.query.type || 'live';

  try {
    // ── CRICKET ──
    if (sport === 'cricket') {
      const raw = await fetchCricket(type);
      if (!raw || raw.status !== 'success' || !raw.data) return res.json({ response: [] });
      const matches = raw.data.slice(0, 8).map((m, i) => ({
        id: 'cr' + i,
        league: m.series_name || m.matchType || 'Cricket',
        home: m.teams && m.teams[0] ? m.teams[0] : 'Team A',
        away: m.teams && m.teams[1] ? m.teams[1] : 'Team B',
        score: m.score && m.score[0] ? m.score[0].r + '/' + m.score[0].w + ' (' + m.score[0].o + ' ov)' : '—',
        away_score: m.score && m.score[1] ? m.score[1].r + '/' + m.score[1].w + ' (' + m.score[1].o + ' ov)' : '—',
        minute: m.status || 'Live',
        matchStarted: m.matchStarted,
        matchEnded: m.matchEnded
      }));
      return res.json({ response: matches });
    }

    // ── FOOTBALL ──
    if (sport === 'football') {
      const raw = await fetchFootball(type);
      if (!raw || !raw.matches) return res.json({ response: [] });
      const matches = raw.matches.slice(0, 8).map((m, i) => ({
        id: 'fo' + i,
        league: m.competition ? m.competition.name : 'Football',
        home: m.homeTeam ? m.homeTeam.shortName || m.homeTeam.name : '?',
        away: m.awayTeam ? m.awayTeam.shortName || m.awayTeam.name : '?',
        score: m.score && m.score.fullTime ? String(m.score.fullTime.home ?? '—') : '—',
        away_score: m.score && m.score.fullTime ? String(m.score.fullTime.away ?? '—') : '—',
        minute: m.minute ? m.minute + "'" : (m.utcDate ? new Date(m.utcDate).toLocaleTimeString('en-IN', { hour:'2-digit', minute:'2-digit' }) : 'Soon'),
        status: m.status
      }));
      return res.json({ response: matches });
    }

    // ── BASKETBALL / MMA / RUGBY (mock) ──
    const mockList = getMockData(sport, type);
    return res.json({ response: mockList });

  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});
app.get('/', (req, res) => res.json({ message: 'MuniyaX Backend Running! ✅' }));

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB Connected!'))
  .catch(err => console.log(err));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
