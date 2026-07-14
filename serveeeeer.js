/**
 * SUPER VULNERABLE DEMO APP
 * -------------------------
 * This file is intentionally insecure for scanner testing.
 * Do NOT deploy this code.
 */

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const child_process = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const _ = require("lodash");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// VULN 1: Insecure CORS configuration
app.use(cors({
  origin: "*",
  credentials: true
}));

// VULN 2: Exposes technology stack
app.disable("etag");
app.set("x-powered-by", true);

// VULN 3: Hardcoded secrets
const JWT_SECRET = "super_secret_jwt_key_123";
const ADMIN_PASSWORD = "admin";
const DATABASE_PASSWORD = "root";
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const STRIPE_SECRET = "sk_live_1234567890abcdef";
const ENCRYPTION_KEY = "1234567890123456";

// VULN 4: In-memory database with plaintext passwords
const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, balance INTEGER, email TEXT)");
  db.run("INSERT INTO users VALUES (1, 'alice', 'alice123', 'user', 1000, 'alice@example.com')");
  db.run("INSERT INTO users VALUES (2, 'bob', 'bob123', 'user', 500, 'bob@example.com')");
  db.run("INSERT INTO users VALUES (3, 'admin', 'admin', 'admin', 999999, 'admin@example.com')");

  db.run("CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, quantity INTEGER, price INTEGER)");
  db.run("INSERT INTO orders VALUES (1, 1, 'Laptop', 1, 1200)");
  db.run("INSERT INTO orders VALUES (2, 2, 'Phone', 1, 800)");

  db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, user_id INTEGER, content TEXT)");
});

// VULN 5: Broken authentication fallback
function weakAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    // Dangerous: unauthenticated users become Alice
    req.user = { id: 1, username: "anonymous", role: "user" };
    return next();
  }

  try {
    const token = authHeader.replace("Bearer ", "");

    // VULN 6: Ignores JWT expiration
    const decoded = jwt.verify(token, JWT_SECRET, {
      ignoreExpiration: true
    });

    req.user = decoded;
    return next();
  } catch (e) {
    // Dangerous: invalid tokens still get access
    req.user = { id: 1, username: "fallback", role: "user" };
    return next();
  }
}

// VULN 7: SQL injection in login
app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.get(query, (err, user) => {
    if (err) {
      return res.status(500).json({
        error: err.message,
        debug_query: query
      });
    }

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // VULN 8: Long-lived JWT with hardcoded secret
    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: "10y" }
    );

    res.json({
      message: "Logged in",
      token,
      user,
      debug_query: query
    });
  });
});

// VULN 9: Anyone can generate an admin token
app.get("/debug/admin-token", (req, res) => {
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

// VULN 10: Admin bypass through query parameter
app.get("/admin", weakAuth, (req, res) => {
  if (req.user.role === "admin" || req.query.admin === "true" || req.headers["x-admin"] === "true") {
    return res.json({
      message: "Welcome admin",
      admin_password: ADMIN_PASSWORD,
      database_password: DATABASE_PASSWORD,
      aws_key: AWS_ACCESS_KEY,
      aws_secret: AWS_SECRET_KEY
    });
  }

  res.status(403).json({ error: "Forbidden" });
});

// VULN 11: IDOR user profile
app.get("/users/:id/profile", weakAuth, (req, res) => {
  const userId = req.params.id;

  const query = `SELECT id, username, role, balance, email FROM users WHERE id = ${userId}`;

  db.get(query, (err, user) => {
    if (err) {
      return res.status(500).json({
        error: err.message,
        query
      });
    }

    res.json({
      profile: user,
      accessed_by: req.user
    });
  });
});

// VULN 12: IDOR orders
app.get("/users/:id/orders", weakAuth, (req, res) => {
  const userId = req.params.id;

  const query = `SELECT * FROM orders WHERE user_id = ${userId}`;

  db.all(query, (err, orders) => {
    if (err) {
      return res.status(500).json({
        error: err.message,
        query
      });
    }

    res.json({
      orders,
      warning: "No ownership check performed"
    });
  });
});

// VULN 13: SQL injection in search
app.get("/search", weakAuth, (req, res) => {
  const q = req.query.q;

  const query = `SELECT * FROM users WHERE username LIKE '%${q}%' OR email LIKE '%${q}%'`;

  db.all(query, (err, rows) => {
    if (err) {
      return res.status(500).json({
        error: err.message,
        query
      });
    }

    res.json({
      results: rows,
      debug_query: query
    });
  });
});

// VULN 14: Mass assignment privilege escalation
app.post("/users/:id/update", weakAuth, (req, res) => {
  const userId = req.params.id;

  // Dangerous: accepts role, balance, password, email, etc.
  const updatedUser = {
    id: userId,
    ...req.body
  };

  res.json({
    message: "User updated",
    updated_user: updatedUser,
    warning: "Mass assignment vulnerability"
  });
});

// VULN 15: Insecure password reset
app.post("/reset-password", (req, res) => {
  const username = req.body.username;
  const newPassword = req.body.newPassword;

  const query = `UPDATE users SET password = '${newPassword}' WHERE username = '${username}'`;

  db.run(query, (err) => {
    if (err) {
      return res.status(500).json({
        error: err.message,
        query
      });
    }

    res.json({
      message: "Password reset without verification",
      username
    });
  });
});

// VULN 16: Negative quantity manipulation
app.post("/checkout", weakAuth, (req, res) => {
  const item = req.body.item || "unknown";
  const price = Number(req.body.price || 100);
  const quantity = Number(req.body.quantity || 1);

  // Dangerous: negative quantity creates negative total
  const total = price * quantity;

  const query = `INSERT INTO orders (user_id, item, quantity, price) VALUES (${req.user.id}, '${item}', ${quantity}, ${price})`;

  db.run(query, (err) => {
    if (err) {
      return res.status(500).json({
        error: err.message,
        query
      });
    }

    res.json({
      message: "Checkout accepted",
      item,
      price,
      quantity,
      total,
      warning: "Negative quantity and client-side price accepted"
    });
  });
});

// VULN 17: Price tampering
app.post("/buy-premium", weakAuth, (req, res) => {
  const clientPrice = Number(req.body.price);

  if (clientPrice <= 1) {
    return res.json({
      message: "Premium activated almost for free",
      charged: clientPrice
    });
  }

  res.json({
    message: "Premium activated",
    charged: clientPrice
  });
});

// VULN 18: Unauthorized money transfer
app.post("/transfer", weakAuth, (req, res) => {
  const fromUser = req.body.fromUser;
  const toUser = req.body.toUser;
  const amount = Number(req.body.amount);

  // Dangerous:
  // - user controls fromUser
  // - no ownership check
  // - negative amount accepted
  // - no transaction safety
  const debitQuery = `UPDATE users SET balance = balance - ${amount} WHERE id = ${fromUser}`;
  const creditQuery = `UPDATE users SET balance = balance + ${amount} WHERE id = ${toUser}`;

  db.run(debitQuery);
  db.run(creditQuery);

  res.json({
    message: "Transfer completed",
    fromUser,
    toUser,
    amount,
    warning: "No authorization or fraud validation"
  });
});

// VULN 19: Command injection
app.get("/ping", (req, res) => {
  const host = req.query.host;

  child_process.exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    res.json({
      host,
      stdout,
      stderr,
      error: error ? error.message : null
    });
  });
});

// VULN 20: Command injection with execSync
app.get("/system/lookup", (req, res) => {
  const domain = req.query.domain;

  try {
    const output = child_process.execSync(`nslookup ${domain}`).toString();

    res.json({
      domain,
      output
    });
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

// VULN 21: Unsafe eval
app.post("/calculate", (req, res) => {
  const expression = req.body.expression;

  const result = eval(expression);

  res.json({
    expression,
    result
  });
});

// VULN 22: Unsafe Function constructor
app.post("/run-code", (req, res) => {
  const code = req.body.code;

  const fn = new Function(code);
  const result = fn();

  res.json({
    result
  });
});

// VULN 23: Server-side template injection style issue
app.post("/template", (req, res) => {
  const template = req.body.template;
  const data = req.body.data || {};

  const compiled = _.template(template);
  const output = compiled(data);

  res.send(output);
});

// VULN 24: Path traversal arbitrary file read
app.get("/download", (req, res) => {
  const file = req.query.file;

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

// VULN 25: Arbitrary file write
app.post("/write-file", weakAuth, (req, res) => {
  const filename = req.body.filename;
  const content = req.body.content;

  const filePath = path.join(__dirname, filename);

  fs.writeFileSync(filePath, content);

  res.json({
    message: "File written",
    filePath
  });
});

// VULN 26: Arbitrary file delete
app.delete("/delete-file", weakAuth, (req, res) => {
  const filename = req.query.filename;

  const filePath = path.join(__dirname, filename);

  fs.unlinkSync(filePath);

  res.json({
    message: "File deleted",
    filePath
  });
});

// VULN 27: SSRF
app.get("/fetch", async (req, res) => {
  const url = req.query.url;

  try {
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

// VULN 28: Open redirect
app.get("/redirect", (req, res) => {
  const next = req.query.next || "https://example.com";

  res.redirect(next);
});

// VULN 29: Reflected XSS
app.get("/hello", (req, res) => {
  const name = req.query.name || "guest";

  res.send(`<h1>Hello ${name}</h1>`);
});

// VULN 30: Stored XSS
app.post("/comments", weakAuth, (req, res) => {
  const content = req.body.content;

  const query = `INSERT INTO comments (user_id, content) VALUES (${req.user.id}, '${content}')`;

  db.run(query, (err) => {
    if (err) {
      return res.status(500).json({
        error: err.message,
        query
      });
    }

    res.json({
      message: "Comment stored",
      content
    });
  });
});

app.get("/comments", (req, res) => {
  db.all("SELECT * FROM comments", (err, comments) => {
    if (err) {
      return res.status(500).json({
        error: err.message
      });
    }

    let html = "<h1>Comments</h1>";

    for (const c of comments) {
      html += `<div>${c.content}</div>`;
    }

    res.send(html);
  });
});

// VULN 31: Prototype pollution
app.post("/settings", weakAuth, (req, res) => {
  const defaults = {
    theme: "light",
    role: "user",
    notifications: true
  };

  const merged = _.merge(defaults, req.body);

  res.json({
    message: "Settings updated",
    settings: merged
  });
});

// VULN 32: Weak hashing MD5
app.post("/hash-password", (req, res) => {
  const password = req.body.password;

  const hash = crypto.createHash("md5").update(password).digest("hex");

  res.json({
    password,
    md5_hash: hash
  });
});

// VULN 33: Weak random token
app.get("/reset-token", (req, res) => {
  const token = Math.random().toString(36).substring(2);

  res.json({
    reset_token: token,
    warning: "Token generated with Math.random"
  });
});

// VULN 34: Insecure encryption mode
app.post("/encrypt", (req, res) => {
  const text = req.body.text || "";

  const cipher = crypto.createCipheriv(
    "aes-128-ecb",
    Buffer.from(ENCRYPTION_KEY),
    null
  );

  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");

  res.json({
    encrypted
  });
});

// VULN 35: Sensitive data exposure
app.get("/debug/env", (req, res) => {
  res.json({
    jwt_secret: JWT_SECRET,
    admin_password: ADMIN_PASSWORD,
    database_password: DATABASE_PASSWORD,
    aws_access_key: AWS_ACCESS_KEY,
    aws_secret_key: AWS_SECRET_KEY,
    stripe_secret: STRIPE_SECRET,
    process_env: process.env
  });
});

// VULN 36: Insecure cookie
app.get("/set-cookie", (req, res) => {
  const token = jwt.sign(
    {
      id: 1,
      username: "alice",
      role: "user"
    },
    JWT_SECRET,
    { expiresIn: "10y" }
  );

  res.cookie("session", token, {
    httpOnly: false,
    secure: false,
    sameSite: "none"
  });

  res.json({
    message: "Insecure session cookie set"
  });
});

// VULN 37: ReDoS risk
app.get("/regex-check", (req, res) => {
  const pattern = req.query.pattern;
  const input = req.query.input || "";

  const regex = new RegExp(pattern);
  const matched = regex.test(input);

  res.json({
    pattern,
    input,
    matched
  });
});

// VULN 38: Authorization bypass by trusting user-controlled role
app.post("/billing/refund", weakAuth, (req, res) => {
  const role = req.body.role;
  const amount = Number(req.body.amount);

  if (role === "admin" || req.user.role === "admin") {
    return res.json({
      message: "Refund approved",
      amount
    });
  }

  res.status(403).json({
    error: "Forbidden"
  });
});

// VULN 39: Business logic bypass with coupon
app.post("/apply-coupon", weakAuth, (req, res) => {
  const cartTotal = Number(req.body.cartTotal);
  const couponValue = Number(req.body.couponValue);

  const finalPrice = cartTotal - couponValue;

  res.json({
    message: "Coupon applied",
    cartTotal,
    couponValue,
    finalPrice,
    warning: "Coupon value is fully client-controlled"
  });
});

// VULN 40: Account deletion without ownership verification
app.delete("/users/:id", weakAuth, (req, res) => {
  const userId = req.params.id;

  res.json({
    message: "User deleted",
    deleted_user_id: userId,
    performed_by: req.user,
    warning: "No ownership or admin check"
  });
});

app.get("/", (req, res) => {
  res.json({
    app: "Super Vulnerable Demo",
    warning: "This app is intentionally vulnerable for scanner testing only.",
    expected_logic_hound_score: "below 30"
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Super vulnerable demo app running on port ${PORT}`);
});
