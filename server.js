const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());


// ===============================
// DATABASE
// ===============================

const db = new Database("portfolio.db");
// ===============================
// CONTACT MESSAGES DATABASE
// ===============================

db.prepare(`
  CREATE TABLE IF NOT EXISTS contact_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    company TEXT DEFAULT '',
    project_type TEXT DEFAULT '',
    message TEXT NOT NULL,
    status TEXT DEFAULT 'New',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

console.log("Contact messages database ready");
db.prepare(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();


// ===============================
// CREATE ADMIN
// ===============================

const adminEmail = process.env.ADMIN_EMAIL;
const adminPassword = process.env.ADMIN_PASSWRD;

if (adminEmail && adminPassword) {

  const existingAdmin = db
    .prepare("SELECT * FROM admins WHERE email = ?")
    .get(adminEmail);

  if (!existingAdmin) {

    const hashedPassword = bcrypt.hashSync(adminPassword, 10);

    db.prepare(`
      INSERT INTO admins (email, password)
      VALUES (?, ?)
    `).run(adminEmail, hashedPassword);

    console.log("Admin account created");

  } else {

    console.log("Admin account already exists");

  }

} else {

  console.log("WARNING: ADMIN_EMAIL or ADMIN_PASSWORD missing in .env");

}


// ===============================
// API HEALTH
// ===============================

app.get("/api/health", (req, res) => {

  res.json({
    success: true,
    message: "Sanjeevi Portfolio Backend is running!"
  });

});
// ===============================
// SAVE CONTACT MESSAGE API
// ===============================

app.post("/api/contact", (req, res) => {
  try {
    const {
      name,
      email,
      company,
      projectType,
      message
    } = req.body;

    // Validate required fields
    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof message !== "string" ||
      !name.trim() ||
      !email.trim() ||
      !message.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "Please provide your name, email, and message."
      });
    }

    // Basic length limits
    if (
      name.length > 100 ||
      email.length > 254 ||
      company?.length > 150 ||
      message.length > 5000 ||
      projectType?.length > 100
    ) {
      return res.status(400).json({
        success: false,
        message: "One or more fields are too long."
      });
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailPattern.test(email.trim())) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email address."
      });
    }

    const result = db.prepare(`
      INSERT INTO contact_messages
      (name, email, company, project_type, message)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      name.trim(),
      email.trim(),
      typeof company === "string" ? company.trim() : "",
      typeof projectType === "string" ? projectType.trim() : "",
      message.trim()
    );

    return res.status(201).json({
      success: true,
      message: "Your message has been submitted successfully.",
      id: result.lastInsertRowid
    });

  } catch (error) {
    console.error("CONTACT SAVE ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to save your message. Please try again."
    });
  }
});
// ===============================
// ADMIN LOGIN API
// ===============================

app.post("/api/auth/login", async (req, res) => {

  try {

    const { email, password } = req.body;

    if (!email || !password) {

      return res.status(400).json({
        success: false,
        message: "Email and password are required"
      });

    }

    const admin = db
      .prepare("SELECT * FROM admins WHERE email = ?")
      .get(email);

    if (!admin) {

      return res.status(401).json({
        success: false,
        message: "Invalid email or password"
      });

    }

    const passwordMatch = await bcrypt.compare(
      password,
      admin.password
    );

    if (!passwordMatch) {

      return res.status(401).json({
        success: false,
        message: "Invalid email or password"
      });

    }

    const token = jwt.sign(
      {
        id: admin.id,
        email: admin.email
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "8h"
      }
    );

    return res.json({
      success: true,
      message: "Login successful",
      token: token
    });

  } catch (error) {

    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Server error"
    });

  }

});

// ===============================
// ADMIN AUTHENTICATION
// ===============================

function requireAdmin(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Please login as admin."
    });
  }

  try {
    const token = authorization.slice(7);

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    const admin = db.prepare(
      "SELECT id, email FROM admins WHERE id = ? AND email = ?"
    ).get(decoded.id, decoded.email);

    if (!admin) {
      return res.status(401).json({
        success: false,
        message: "Admin account not found."
      });
    }

    req.admin = admin;
    next();

  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Session expired. Please login again."
    });
  }
}

// ===============================
// GET CONTACT MESSAGES
// ===============================

app.get(
  "/api/admin/messages",
  requireAdmin,
  (req, res) => {
    try {
      const messages = db.prepare(`
        SELECT
          id,
          name,
          email,
          company,
          project_type,
          message,
          status,
          created_at
        FROM contact_messages
        ORDER BY id DESC
        LIMIT 500
      `).all();

      return res.json({
        success: true,
        messages
      });

    } catch (error) {
      console.error("ADMIN MESSAGES ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to load contact messages."
      });
    }
  }
);
// ===============================
// SERVE PORTFOLIO
// ===============================

app.use(express.static(path.join(__dirname)));


// ===============================
// START SERVER
// ===============================

app.listen(PORT, () => {

  console.log(`Server running at http://localhost:${PORT}`);

});