
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app= express();
const cors=require('cors');

require("dotenv").config();
app.use(cors());
app.use(express.json({ limit: "30mb", extended: true }));
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.json());


mongoose.connect(process.env.DB_CONNECTION, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});


const crypto = require("crypto");

const generateSecretKey = () => {
    
       return crypto.randomBytes(32).toString('hex');
     };
     

     const secretKey = generateSecretKey();


const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  role: String, 
});
       

const accountSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  balance: Number,
  transactions: [{
    type: String, 
    amount: Number,
    timestamp: { type: Date, default: Date.now },
  }],
});


const User = mongoose.model('User', userSchema);
const Account = mongoose.model('Account', accountSchema);


app.use(bodyParser.json());

app.post("/register", async (req, res) => {
       try {
         const { email, password, userType ,role} = req.body;
     
         const hashedPassword = await bcrypt.hash(password, 10);
     
         const user = new User({
           email,
           password: hashedPassword,
           userType,
           role
         });
     
         await user.save();
     
         res.status(201).json({ message: "User registered successfully" });
       } catch (error) {
         console.error(error);
         res.status(500).json({ error: "Internal Server Error" });
       }
     });

app.post('/login/customer', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || user.role !== 'customer') {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const accessToken = jwt.sign({ userId: user._id }, 'secretkey', { expiresIn: '1h' });
    res.json({ accessToken });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});




app.post('/login/banker', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || user.role !== 'banker') {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const accessToken = jwt.sign({ userId: user._id }, 'secretkey', { expiresIn: '1h' });
    res.json({ accessToken });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});


const authenticateToken = (req, res, next) => {
       const token = req.header("Authorization");
     
       if (!token) return res.status(401).json({ error: "Unauthorized" });
     
       jwt.verify(token, secretKey, (err, user) => {
         if (err) {
           console.error("JWT verification error:", err);
           return res.status(403).json({ error: "Forbidden" });
         }
         req.user = user;
         next();
       });
     };


app.get('/transactions', authenticateToken, async (req, res) => {
  try {
    const account = await Account.findOne({ userId: req.userId });
    res.json({ balance: account.balance, transactions: account.transactions });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});






app.post('/deposit', authenticateToken, async (req, res) => {
  const { amount } = req.body;

  try {
    const account = await Account.findOne({ userId: req.userId });
    console.log(account.balance, account.transactions);
    account.balance += amount;
    account.transactions.push({ type: 'deposit', amount });
    await account.save();
    res.json({ message: 'Deposit successful' });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});





app.post('/withdraw', authenticateToken, async (req, res) => {
  const { amount } = req.body;

  try {
    const account = await Account.findOne({ userId: req.userId });
    if (account.balance < amount) {
      return res.status(400).json({ message: 'Insufficient funds' });
    }

    account.balance -= amount;
    account.transactions.push({ type: 'withdrawal', amount });
    await account.save();
    res.json({ message: 'Withdrawal successful' });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});





const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
