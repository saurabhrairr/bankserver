const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
const cors = require("cors");

require("dotenv").config();
app.use(cors());
app.use(express.json({ limit: "30mb", extended: true }));
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.json());

mongoose.connect(process.env.DB_CONNECTION, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Generate a secret key for JWT
const crypto = require("crypto");
const generateSecretKey = () => {
  return crypto.randomBytes(32).toString("hex");
};
const secretKey = generateSecretKey();

// Schema definitions
const userSchema = new mongoose.Schema({
  username: String,
  email: {
    type: String,
    unique: true
  },
  password: String,
  role: String,
});


const accountSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  balance: Number,
  transactions: [
    {
      type: String,
      amount: Number,
      timestamp: { type: Date, default: Date.now },
    },
  ],
});

// Model definitions
const User = mongoose.model("User", userSchema);
const Account = mongoose.model("Account", accountSchema);

// Register endpoint
app.post("/register", async (req, res) => {
  try {
    const { email, password, userType, role } = req.body;
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res
        .status(400)
        .json({ error: "User with this email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      email,
      password: hashedPassword,
      userType,
      role,
    });

    await user.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


app.get("/user/:email", async (req, res) => {
  try {
    const { email } = req.params;
    const user = await User.findOne({ email });
    res.json({ exists: !!user }); // Send true if user exists, false otherwise
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


// Customer login endpoint
app.post("/login/customer", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || user.role !== "customer") {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    const accessToken = jwt.sign({ userId: user._id }, secretKey, {
      expiresIn: "1h",
    });
    res.json({ accessToken });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
});

// Banker login endpoint (similar to customer login)

// Middleware for token authentication
// Middleware for token authentication
function verifyToken(req, res, next) {
  // Check if the Authorization header is present
  if (!req.headers.authorization) {
    return res.status(401).send({ message: "Authorization header missing" });
  }

  // Split the Authorization header to extract the token
  let token = req.headers.authorization.split(" ")[1];

  // Verify the token using the correct secret key
  jwt.verify(token, secretKey, (err, data) => {
    if (!err) {
      // Store the user ID from the token payload in the request object
      req.userId = data.userId;
      next();
    } else {
      res.status(401).send({ message: "Invalid Token please login again" });
    }
  });
}



// Protected route to get transactions
app.get("/transactions", verifyToken, async (req, res) => {
  try {
    const account = await Account.findOne({ userId: req.userId });
    res.json({ balance: account.balance, transactions: account.transactions });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
});

// Deposit and withdraw endpoints (similar to customer login)

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

app.post("/deposit", verifyToken, async (req, res) => {
  const { amount } = req.body;

  try {
    const userId = req.userId;

    console.log("User ID:", userId); // Log the user ID

    const account = await Account.findOne({ userId });
    console.log("Account:", account); // Log the account

    if (!account) {
      return res.status(404).json({ message: "Account not found" });
    }

    account.balance += amount;
    account.transactions.push({ type: "deposit", amount });
    await account.save();

    res.json({ message: "Deposit successful" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});


app.post("/withdraw", verifyToken, async (req, res) => {
  const { amount } = req.body;

  try {
    const account = await Account.findOne({ userId: req.userId });
    if (account.balance < amount) {
      return res.status(400).json({ message: "Insufficient funds" });
    }

    account.balance -= amount;
    account.transactions.push({ type: "withdrawal", amount });
    await account.save();
    res.json({ message: "Withdrawal successful" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
});
