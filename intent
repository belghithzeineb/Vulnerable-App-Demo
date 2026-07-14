/**
 * Intentionally Vulnerable App Demo
 * ---------------------------------
 * This file is designed for security scanner testing only.
 * Do NOT deploy this application.
 */

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const child_process = require("child_process");
const fs = require("fs");
const path = require("path");
const _ = require("lodash");

const app = express();

app.use(express.json());

// 1. Insecure CORS: allows every origin with credentials
app.use(cors({
  origin: "*",
  credentials: true
}));

// 2. Hardcoded secrets
const JWT_SECRET = "admin123";
const ADMIN_PASSWORD = "password";
const STRIPE_SECRET_KEY = "sk_live_hardcoded_secret_123456";
const DATABASE_PASSWORD = "root:root";

// 3. In-memory database
const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, balance INTEGER)");
  db.run("INSERT INTO users VALUES (1, 'alice', 'alice123', 'user', 1000)");
  db.run("INSERT INTO users VALUES (2, 'bob', 'bob123', 'user', 500)");
  db.run("INSERT INTO users VALUES (3, 'admin', 'password', 'admin', 999999)");

  db.run("CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, product TEXT, quantity INTEGER, total INTEGER)");
  db.run("INSERT INTO orders VALUES (1, 1, 'Laptop', 1, 1200)");
  db.run("INSERT INTO orders VALUES (2, 2, 'Phone', 1, 800)");
});

// 4. Weak authentication middleware
function weakAuth(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    // Vulnerability: anonymous users become user 1
    req.user = { id: 1, username: "guest", role: "user" };
    return next();
  }

  try {
    // Vulnerability: ignores token expiration
    const decoded = jwt.verify(token.replace("Bearer ", ""), JWT_SECRET, {
      ignoreExpiration: true
    });

    req.user = decoded;
    next();
  } catch (e) {
    // Vulnerability: failed token parsing still grants default access
    req.user = { id: 1, username: "fallback", role: "user" };
    next();
  }
}

// 5. SQL Injection login
app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Critical: direct string interpolation into SQL query
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.get(query, (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message, query });
    }

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: "365d" }
    );

    res.json({
      message: "Logged in",
      token,
      user,
      debug_query: query
    });
  });
});

// 6. Admin authentication bypass
app.get("/admin", weakAuth, (req, res) => {
  // Critical business logic flaw: query parameter grants admin access
  if (req.user.role === "admin" || req.query.admin === "true") {
    return res.json({
      message: "Welcome admin",
      secret: "production-admin-panel-secret",
      database_password: DATABASE_PASSWORD
    });
  }

  res.status(403).json({ error: "Forbidden" });
});

// 7. IDOR: access any user profile by changing ID
app.get("/users/:id/profile", weakAuth, (req, res) => {
  const userId = req.params.id;

  // Critical: no ownership check
  const query = `SELECT id, username, role, balance FROM users WHERE id = ${userId}`;

  db.get(query, (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message, query });
    }

    res.json({
      profile: user,
      accessed_by: req.user
    });
  });
});

// 8. IDOR: access any user's orders
app.get("/users/:id/orders", weakAuth, (req, res) => {
  const userId = req.params.id;

  // Critical: no check that req.user.id === userId
  const query = `SELECT * FROM orders WHERE user_id = ${userId}`;

  db.all(query, (err, orders) => {
    if (err) {
      return res.status(500).json({ error: err.message, query });
    }

    res.json({
      orders,
      warning: "No authorization check performed"
    });
  });
});

// 9. Negative quantity manipulation
app.post("/checkout", weakAuth, (req, res) => {
  const product = req.body.product || "Unknown";
  const price = Number(req.body.price || 100);
  const quantity = Number(req.body.quantity || 1);

  // Critical business logic flaw:
  // Negative quantity creates negative total and can increase user balance/refund.
  const total = price * quantity;

  db.run(
    `INSERT INTO orders (user_id, product, quantity, total) VALUES (${req.user.id}, '${product}', ${quantity}, ${total})`,
    (err) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      res.json({
        message: "Order accepted",
        product,
        price,
        quantity,
        total,
        warning: "Negative quantities are accepted"
      });
    }
  );
});

// 10. Price tampering
app.post("/buy-premium", weakAuth, (req, res) => {
  // Critical business logic flaw:
  // Client controls price directly.
  const clientProvidedPrice = Number(req.body.price);

  if (clientProvidedPrice <= 1) {
    return res.json({
      message: "Premium subscription activated for almost free",
      charged: clientProvidedPrice
    });
  }

  res.json({
    message: "Premium subscription activated",
    charged: clientProvidedPrice
  });
});

// 11. Command injection
app.get("/network/ping", (req, res) => {
  const host = req.query.host;

  // Critical: user input passed directly to shell
  child_process.exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    res.json({
      host,
      stdout,
      stderr,
      error: error ? error.message : null
    });
  });
});

// 12. Path traversal arbitrary file read
app.get("/download", (req, res) => {
  const file = req.query.file;

  // Critical: user controls file path
  const filePath = path.join(__dirname, file);

  try {
    const content = fs.readFileSync(filePath, "utf8");
    res.send(content);
  } catch (e) {
    res.status(500).json({
      error: e.message,
      attempted_path: filePath
    });
  }
});

// 13. Unsafe eval
app.post("/calculate", (req, res) => {
  const expression = req.body.expression;

  // Critical: arbitrary code execution
  const result = eval(expression);

  res.json({
    expression,
    result
  });
});

// 14. SSRF
app.get("/fetch", async (req, res) => {
  const url = req.query.url;

  try {
    // Critical: server fetches arbitrary user-controlled URL
    const response = await fetch(url);
    const text = await response.text();

    res.send(text);
  } catch (e) {
    res.status(500).json({
      error: e.message,
      url
    });
  }
});

// 15. Open redirect
app.get("/redirect", (req, res) => {
  const next = req.query.next || "https://example.com";

  // High: redirects to arbitrary external URL
  res.redirect(next);
});

// 16. Prototype pollution via lodash merge
app.post("/settings", weakAuth, (req, res) => {
  const defaults = {
    theme: "light",
    notifications: true,
    role: "user"
  };

  // High: unsafe deep merge of user-controlled object
  const merged = _.merge(defaults, req.body);

  res.json({
    message: "Settings updated",
    settings: merged
  });
});

// 17. Mass assignment privilege escalation
app.post("/users/:id/update", weakAuth, (req, res) => {
  const userId = req.params.id;

  // Critical business logic flaw:
  // User can update role, balance, or any sensitive field.
  const updates = req.body;

  res.json({
    message: "User updated",
    user_id: userId,
    updated_fields: updates,
    warning: "Mass assignment allows privilege escalation"
  });
});

// 18. Insecure password reset
app.post("/reset-password", (req, res) => {
  const username = req.body.username;
  const newPassword = req.body.newPassword;

  // Critical: no token, no email verification, no identity proof
  const query = `UPDATE users SET password = '${newPassword}' WHERE username = '${username}'`;

  db.run(query, (err) => {
    if (err) {
      return res.status(500).json({ error: err.message, query });
    }

    res.json({
      message: "Password reset successful without verification",
      username
    });
  });
});

// 19. Debug endpoint exposing secrets
app.get("/debug/env", (req, res) => {
  res.json({
    jwt_secret: JWT_SECRET,
    admin_password: ADMIN_PASSWORD,
    stripe_secret_key: STRIPE_SECRET_KEY,
    database_password: DATABASE_PASSWORD,
    environment: process.env
  });
});

// 20. Insecure direct balance transfer
app.post("/transfer", weakAuth, (req, res) => {
  const fromUser = req.body.fromUser;
  const toUser = req.body.toUser;
  const amount = Number(req.body.amount);

  // Critical business logic flaws:
  // - user controls source account
  // - no ownership check
  // - negative amount can reverse transfer
  // - no transaction safety
  // - no balance validation
  const debitQuery = `UPDATE users SET balance = balance - ${amount} WHERE id = ${fromUser}`;
  const creditQuery = `UPDATE users SET balance = balance + ${amount} WHERE id = ${toUser}`;

  db.run(debitQuery);
  db.run(creditQuery);

  res.json({
    message: "Transfer completed",
    fromUser,
    toUser,
    amount,
    warning: "No authorization, validation, or fraud checks"
  });
});

// 21. Weak JWT generation endpoint
app.get("/debug/make-admin-token", (req, res) => {
  // Critical: anyone can generate admin token
  const token = jwt.sign(
    {
      id: 3,
      username: "admin",
      role: "admin"
    },
    JWT_SECRET,
    { expiresIn: "10y" }
  );

  res.json({
    message: "Admin token generated",
    token
  });
});

app.get("/", (req, res) => {
  res.json({
    app: "Vulnerable App Demo",
    warning: "This app is intentionally vulnerable and must not be deployed.",
    expected_logic_hound_score: "below 20"
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Vulnerable demo app running on port ${PORT}`);
});
