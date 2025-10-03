import express from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 4000;
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "access_secret_key";
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "refresh_secret_key";

let refreshTokens = []; // in-memory, replace with DB in production

// Generate tokens
const generateAccessToken = (user) =>
  jwt.sign(user, ACCESS_SECRET, { expiresIn: "15m" });
const generateRefreshToken = (user) => {
  const token = jwt.sign(user, REFRESH_SECRET, { expiresIn: "7d" });
  refreshTokens.push(token);
  return token;
};

// Login
app.post("/login", (req, res) => {
  const { username } = req.body;
  const user = { name: username };
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  res.json({ accessToken, refreshToken });
});

// Refresh
app.post("/refresh", (req, res) => {
  const { token } = req.body;
  if (!token || !refreshTokens.includes(token)) return res.sendStatus(403);
  jwt.verify(token, REFRESH_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken });
  });
});

// Logout
app.post("/logout", (req, res) => {
  const { token } = req.body;
  refreshTokens = refreshTokens.filter((t) => t !== token);
  res.sendStatus(204);
});

// Protected route
app.get("/protected", authenticate, (req, res) => {
  res.json({ message: `Hello ${req.user.name}, you are authorized.` });
});

function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, ACCESS_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
