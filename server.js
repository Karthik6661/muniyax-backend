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
  password: { type: String, required: true },
  balance: { type: Number, default: 10000 },
  verified: { type: Boolean, default: false }
});
const User = mongoose.model('User', UserSchema);

const OtpSchema = new mongoose.Schema({
  email: String,
  otp: String,
  createdAt: { type: Date, default: Date.now, expires: 300 }
});
const Otp = mongoose.model('Otp', OtpSchema);

// Send OTP
async function sendOTP(email, otp) {
  await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': process.env.BREVO_API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      sender: { name: 'MuniyaX', email: 'noreply@muniyax.com' },
      to: [{ email }],
      subject: 'MuniyaX OTP Verification',
      htmlContent: `<h2>Your OTP: <b>${otp}</b></h2><p>Valid for 5 minutes.</p>`
    })
  });
}

// Request OTP
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

// SIGNUP with OTP
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

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: 'Wrong password' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { username: user.username, balance: user.balance, avatar: '🎮' } });
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
