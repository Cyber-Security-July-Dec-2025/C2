const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { createServer } = require("http");
const { Server } = require("socket.io");
require("dotenv").config();

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    methods: ["GET", "POST"],
  },
});


app.use(cors());
app.use(express.json({ limit: "10mb" }));

// MongoDB connection
mongoose.connect(
  process.env.MONGODB_URI || "mongodb://localhost:27017/pgp-messaging",
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  }
);

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  passphrase: { type: String, required: true },
  publicKey: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

// Message Schema
const messageSchema = new mongoose.Schema({
  from: { type: String, required: true },
  to: { type: String, required: true },
  wrappedKey: { type: String, required: true },
  ciphertext: { type: String, required: true },
  iv: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Message = mongoose.model("Message", messageSchema);

// Routes
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password, passphrase, publicKey } = req.body;

    // Check if username already exists
    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      return res.status(400).json({ error: "Username already exists" });
    }

    // Check if email already exists
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ error: "Email already exists" });
    }

    // Hash password and passphrase
    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedPassphrase = await bcrypt.hash(passphrase, 10);

    const user = new User({
      username,
      email,
      password: hashedPassword,
      passphrase: hashedPassphrase,
      publicKey,
    });
    await user.save();

    res.json({ message: "User registered successfully", username });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;

    // Find user by username or email
    const user = await User.findOne({
      $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }],
    });

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    res.json({
      message: "Login successful",
      username: user.username,
      email: user.email,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/publicKey/:username", async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({ publicKey: user.publicKey });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/messages", async (req, res) => {
  try {
    const { from, to, wrappedKey, ciphertext, iv } = req.body;

    const recipient = await User.findOne({ username: to });
    if (!recipient) {
      return res.status(404).json({ error: "Recipient not found" });
    }

    const message = new Message({ from, to, wrappedKey, ciphertext, iv });
    await message.save();

    // Emit real-time message to recipient if connected
    io.to(to).emit("newMessage", {
      id: message._id,
      from,
      wrappedKey,
      ciphertext,
      iv,
      timestamp: message.timestamp,
    });

    res.json({ message: "Message sent successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/messages/:username", async (req, res) => {
  try {
    const messages = await Message.find({ to: req.params.username }).sort({
      timestamp: -1,
    });
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/users", async (req, res) => {
  try {
    const users = await User.find({}, "username");
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Socket.IO connection handling
io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  socket.on("join", (username) => {
    socket.join(username);
    console.log(`${username} joined their room`);
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

const PORT = process.env.PORT || 5001;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
