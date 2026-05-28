const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json());

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
    const user = new User({ username, email, password: hashed, verified: true });
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
      user = new User({ username, email, googleId, verified: true, balance: 10000 });
      await user.save();
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { username: user.username, balance: user.balance, avatar: '🎮' } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Admin middleware
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

// Admin login
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== process.env.ADMIN_PASSWORD) return res.status(401).json({ message: 'Wrong password' });
  const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1d' });
  res.json({ token });
});

// Admin stats
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const bannedUsers = await User.countDocuments({ banned: true });
    const totalBalance = await User.aggregate([{ $group: { _id: null, total: { $sum: '$balance' } } }]);
    const today = new Date(); today.setHours(0,0,0,0);
    res.json({ totalUsers, bannedUsers, totalBalance: totalBalance[0]?.total || 0 });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get all users
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find({}, 'username email balance verified banned createdAt');
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Ban/unban user
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

// Edit balance
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
app.get('/', (req, res) => res.json({ message: 'MuniyaX Backend Running!' }));

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB Connected!'))
  .catch(err => console.log(err));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
