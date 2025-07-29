const express = require("express");
const bcrypt = require("bcrypt");
const { encryptData, decryptData } = require("./cryptoUtils");
const crypto = require("crypto");

const app = express();
app.use(express.json());

let storedHashedPassword;
let storedEncryptedMemberId;

const secretKey = crypto.randomBytes(32); // In production, use a secure, persistent key

app.post("/register", async (req, res) => {
  const { password, memberId } = req.body;
  if (!password || !memberId)
    return res.status(400).json({ error: "Password and memberId are required" });

  const saltRounds = 10;
  storedHashedPassword = await bcrypt.hash(password, saltRounds);

  storedEncryptedMemberId = encryptData(memberId, secretKey);

  res.json({
    message: "Password and memberId stored securely!",
    hashed: storedHashedPassword,
    encryptedMemberId: storedEncryptedMemberId,
  });
});

app.post("/login", async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Password is required" });

  if (!storedHashedPassword)
    return res.status(400).json({ error: "No password registered yet." });

  const isMatch = await bcrypt.compare(password, storedHashedPassword);
  if (!isMatch) return res.status(401).json({ error: "Invalid password" });

  const decryptedMemberId = decryptData(storedEncryptedMemberId, secretKey);

  res.json({
    message: "Password is correct!",
    memberId: decryptedMemberId,
  });
});


// Start server
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
