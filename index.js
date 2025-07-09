import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import http from "http";
import { Server as SocketIOServer } from "socket.io";

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: ["http://localhost:5173", "https://feedback-backend-zwut.onrender.com"],
    methods: ["GET", "POST"],
    credentials: true,
  },
});
app.use(
  cors({
    origin: ["http://localhost:5173"],
    credentials: true,
  })
);
app.use(express.json());

// Socket.IO chat logic
io.on("connection", (socket) => {
  console.log("A user connected: " + socket.id);
  socket.on("chat message", (msg) => {
    io.emit("chat message", msg); // broadcast to all
  });
  socket.on("disconnect", () => {
    console.log("User disconnected: " + socket.id);
  });
});

server.listen(3000, function () {
  console.log("server running at localhost:3000");
});

//connect the database using mongoose

mongoose
  .connect(process.env.MONGODB_URL)
  .then(function () {
    console.log("connected to database");
  })
  .catch(function (err) {
    console.log(err);
  });

//create schema from database

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

//create schema for feedback with timestamps
const feedbackSchema = new mongoose.Schema(
  {
    name: String,
    message: String,
  },
  { timestamps: true }
);

// Message schema for private chat
const messageSchema = new mongoose.Schema({
  from: String, // sender email
  to: String,   // recipient email
  content: String,
  timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model("Message", messageSchema);

//create model for the model
const User = mongoose.model("User", userSchema);

//create model for feedback
const Feedback = mongoose.model("Feedback", feedbackSchema);

//login api
app.post("/login", async function (req, res) {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Password not matching" });
    }
    // Sign token with email as object
    const token = jwt.sign({ email }, "secret_key");
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: "Login failed", error: err.message });
  }
});

// Admin login route
app.post("/admin/login", async function (req, res) {
  let { email, password } = req.body;
  email = email.trim().toLowerCase();
  // Only allow the admin email
  if (email !== "surajyadav91429@gmail.com") {
    return res.status(403).json({ message: "Access denied: Not an admin. Email used: " + email });
  }
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "Admin not found. Please create the admin user first." });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Password not matching. Please check your password." });
    }
    // Sign token with admin flag
    const token = jwt.sign({ email, isAdmin: true }, "secret_key");
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: "Admin login failed", error: err.message });
  }
});

// Endpoint to (re)create admin user if not exists
app.post("/admin/create", async (req, res) => {
  const { email, password } = req.body;
  if (email !== "surajyadav91429@gmail.com") {
    return res.status(403).json({ message: "Only the main admin email can be created." });
  }
  try {
    let user = await User.findOne({ email });
    if (user) {
      console.log("Admin already exists:", email);
      return res.status(409).json({ message: "Admin already exists." });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    user = new User({ email, password: hashedPassword });
    await user.save();
    console.log("Admin user created:", email);
    res.json({ message: "Admin user created successfully." });
  } catch (err) {
    console.error("Failed to create admin user:", err);
    res.status(500).json({ message: "Failed to create admin user", error: err.message });
  }
});

// Auth middleware for protected routes
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });
  jwt.verify(token, "secret_key", (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// Admin-only middleware
function requireAdmin(req, res, next) {
  if (!req.user || !req.user.isAdmin || req.user.email !== "surajyadav91429@gmail.com") {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
}

// Protected feedback POST route
app.post(
  "/feedback",
  authenticateToken,
  async (req, res) => {
    const { name, message } = req.body;
    try {
      const feedback = new Feedback({ name, message });
      const result = await feedback.save();
      res.status(201).json({ message: "Feedback submitted", feedback: result });
    } catch (err) {
      res
        .status(500)
        .json({ message: "Feedback submission failed", error: err.message });
    }
  }
);

// Get all feedbacks (admin only)
app.get("/admin/feedbacks", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const feedbacks = await Feedback.find({}).sort({ createdAt: -1 });
    res.json(feedbacks);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch feedbacks", error: err.message });
  }
});

app.get("/feedbacks", authenticateToken, async (req, res) => {
  try {
    // Only allow admin email to access feedbacks
    if (req.user.email !== "surajyadav91429@gmail.com") {
      return res.status(403).json({ message: "Access denied: Admins only" });
    }
    const feedbacks = await Feedback.find({}).sort({ createdAt: -1 });
    res.json(feedbacks);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch feedbacks", error: err.message });
  }
});

// Delete feedback by ID (admin only)
app.delete("/admin/feedbacks/:id", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await Feedback.findByIdAndDelete(id);
    if (!deleted) {
      return res.status(404).json({ message: "Feedback not found" });
    }
    res.json({ message: "Feedback deleted" });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete feedback", error: err.message });
  }
});

app.delete("/feedbacks/:id", authenticateToken, async (req, res) => {
  try {
    console.log("DELETE /feedbacks/:id called", req.user, req.params.id);
    if (req.user.email !== "surajyadav91429@gmail.com") {
      console.log("Access denied: not admin", req.user.email);
      return res.status(403).json({ message: "Access denied: Admins only" });
    }
    const { id } = req.params;
    const deleted = await Feedback.findByIdAndDelete(id);
    if (!deleted) {
      console.log("Feedback not found for id:", id);
      return res.status(404).json({ message: "Feedback not found" });
    }
    console.log("Feedback deleted:", id);
    res.json({ message: "Feedback deleted" });
  } catch (err) {
    console.error("Failed to delete feedback:", err);
    res.status(500).json({ message: "Failed to delete feedback", error: err.message });
  }
});

// Get feedbacks for the logged-in user
app.get("/my-feedbacks", authenticateToken, async (req, res) => {
  try {
    const userEmail = req.user.email;
    const feedbacks = await Feedback.find({ name: userEmail }).sort({ createdAt: -1 });
    res.json(feedbacks);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch your feedbacks", error: err.message });
  }
});

// Edit feedback by ID (user only)
app.put("/feedbacks/:id", authenticateToken, async (req, res) => {
  try {
    const userEmail = req.user.email;
    const { id } = req.params;
    const { message } = req.body;
    const feedback = await Feedback.findById(id);
    if (!feedback) {
      return res.status(404).json({ message: "Feedback not found" });
    }
    if (feedback.name !== userEmail) {
      return res.status(403).json({ message: "You can only edit your own feedback" });
    }
    feedback.message = message;
    await feedback.save();
    res.json({ message: "Feedback updated", feedback });
  } catch (err) {
    res.status(500).json({ message: "Failed to update feedback", error: err.message });
  }
});

// Get all users (for chat list)
app.get("/users", authenticateToken, async (req, res) => {
  try {
    const users = await User.find({}, "email");
    res.json(users.map(u => u.email));
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch users", error: err.message });
  }
});

// Get message history between two users
app.get("/messages/:otherEmail", authenticateToken, async (req, res) => {
  try {
    const userEmail = req.user.email;
    const otherEmail = req.params.otherEmail;
    const messages = await Message.find({
      $or: [
        { from: userEmail, to: otherEmail },
        { from: otherEmail, to: userEmail }
      ]
    }).sort({ timestamp: 1 });
    res.json(messages);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch messages", error: err.message });
  }
});

// Socket.IO private messaging
io.on("connection", (socket) => {
  let userEmail = null;
  socket.on("register", (email) => {
    userEmail = email;
    socket.join(email); // join a room for this user
  });
  socket.on("private message", async ({ to, content }) => {
    if (!userEmail) return;
    const msg = { from: userEmail, to, content, timestamp: new Date() };
    await Message.create(msg);
    io.to(to).to(userEmail).emit("private message", msg);
  });
  socket.on("disconnect", () => {
    // Optionally handle disconnect
  });
});