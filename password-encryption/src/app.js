const express = require("express");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json()); // To parse JSON body

// Simulating a stored password hash (this would normally be in a database)
let storedHashedPassword;

// Endpoint to register a new password (hash and store it)
app.post("/register", async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Password is required" });

  const saltRounds = 10;
  storedHashedPassword = await bcrypt.hash(password, saltRounds);
  res.json({ message: "Password stored securely!", hashed: storedHashedPassword });
});

// Endpoint to verify the password
app.post("/login", async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Password is required" });

  if (!storedHashedPassword) {
    return res.status(400).json({ error: "No password registered yet." });
  }

  const isMatch = await bcrypt.compare(password, storedHashedPassword);
  if (isMatch) {
    res.json({ message: "Password is correct!" });
  } else {
    res.status(401).json({ error: "Invalid password" });
  }
});

// Start server
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
