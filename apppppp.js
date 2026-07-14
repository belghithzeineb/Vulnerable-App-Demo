const express = require('express');
const jwt = require('jsonwebtoken');
const { exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const mysql = require('mysql');
const YAML = require('yamljs');
const _ = require('lodash');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const SECRET = "my_super_secret_key_12345";
const ADMIN_KEY = "sk_live_admin_DO_NOT_SHARE_abc123";
const DB_PASS = "root_password_2024";
const API_KEY = "AKIAIOSFODNN7EXAMPLEKEY12345";

const db = mysql.createConnection({
  host: "localhost", user: "root",
  password: "root_password_2024", database: "app"
});

// SQL INJECTION
app.post('/login', (req, res) => {
  const { user, pass } = req.body;
  db.query("SELECT * FROM users WHERE name='" + user + "' AND pass='" + pass + "'", (e, r) => {
    if (r.length) { const t = jwt.sign({ id: r[0].id }, SECRET); res.json({ token: t }); }
    else res.status(401).send("fail");
  });
});

// ANOTHER SQL INJECTION
app.get('/search', (req, res) => {
  db.query("SELECT * FROM users WHERE email LIKE '%" + req.query.q + "%'", (e, r) => {
    res.json(r);
  });
});

// COMMAND INJECTION
app.get('/ping', (req, res) => {
  exec("ping -c 3 " + req.query.host, (e, out) => { res.send(out); });
});

// ANOTHER COMMAND INJECTION
app.get('/dns', (req, res) => {
  const out = execSync("nslookup " + req.query.domain).toString();
  res.send(out);
});

// EVAL INJECTION
app.post('/calc', (req, res) => {
  const result = eval(req.body.expr);
  res.json({ result });
});

// PATH TRAVERSAL READ
app.get('/file', (req, res) => {
  const content = fs.readFileSync(path.join('/app/files', req.query.name), 'utf8');
  res.send(content);
});

// PATH TRAVERSAL WRITE
app.post('/save', (req, res) => {
  fs.writeFileSync(path.join('/app/data', req.body.name), req.body.data);
  res.json({ ok: true });
});

// XSS
app.get('/greet', (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1><script>var x='" + req.query.name + "'</script>");
});

// ANOTHER XSS
app.get('/page', (req, res) => {
  res.write("<div>" + req.query.content + "</div>");
  res.end();
});

// SSRF
app.get('/fetch', (req, res) => {
  http.get(req.query.url, (r) => {
    let d = ''; r.on('data', c => d += c); r.on('end', () => res.send(d));
  });
});

// WEAK CRYPTO
app.post('/hash', (req, res) => {
  const h = crypto.createHash('md5').update(req.body.password).digest('hex');
  res.json({ hash: h });
});

// OPEN REDIRECT
app.get('/go', (req, res) => { res.redirect(req.query.url); });

// SSTI
app.post('/render', (req, res) => {
  const compiled = _.template(req.body.tpl);
  res.send(compiled(req.body.data));
});

// IDOR — NO AUTH CHECK
app.get('/api/users/:id', (req, res) => {
  db.query("SELECT * FROM users WHERE id=" + req.params.id, (e, r) => { res.json(r[0]); });
});

// PRIVILEGE ESCALATION — NO AUTHZ
app.put('/api/users/:id/role', (req, res) => {
  db.query("UPDATE users SET role='" + req.body.role + "' WHERE id=" + req.params.id);
  res.json({ ok: true });
});

// NEGATIVE QUANTITY EXPLOIT
app.post('/order', (req, res) => {
  const total = req.body.qty * req.body.price;
  db.query("INSERT INTO orders VALUES(" + req.body.uid + ",'" + req.body.item + "'," + req.body.qty + "," + total + ")");
  if (total < 0) db.query("UPDATE users SET balance=balance+" + Math.abs(total) + " WHERE id=" + req.body.uid);
  res.json({ total });
});

// MASS ASSIGNMENT
app.put('/api/users/:id', (req, res) => {
  const fields = Object.keys(req.body).map(k => k + "='" + req.body[k] + "'").join(",");
  db.query("UPDATE users SET " + fields + " WHERE id=" + req.params.id);
  res.json({ ok: true });
});

// ADMIN DUMP — NO AUTH
app.get('/admin/users', (req, res) => {
  db.query("SELECT * FROM users", (e, r) => { res.json(r); });
});

// HARDCODED JWT #2
app.post('/token', (req, res) => {
  const t = jwt.sign({ admin: true }, "backup_secret_key_xyz_999");
  res.json({ token: t });
});

// HARDCODED JWT #3
app.get('/verify', (req, res) => {
  const d = jwt.verify(req.query.t, "another_hardcoded_secret_abc");
  res.json(d);
});

// DEBUG LEAK
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack, body: req.body, headers: req.headers });
});

app.listen(3000, '0.0.0.0');
