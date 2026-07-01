// server.js
const express = require('express');
const { exec } = require('child_process');
const mysql = require('mysql2');
const fs = require('fs');

const app = express();
app.use(express.json());

// 🚨 CRITICAL 1: Hardcoded Secret Keys & DB Credentials
const JWT_SECRET = "super-secret-key-that-is-hardcoded-12345!";
const db_config = {
    host: 'localhost',
    user: 'db_admin_root',
    password: 'password_super_secure_9999!',
    database: 'production_db'
};

const connection = mysql.createConnection(db_config);

// 🚨 CRITICAL 2: SQL Injection (Classic dynamic string concat)
app.post('/api/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    
    const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    
    connection.query(query, (err, results) => {
        if (err) return res.status(500).json(err);
        res.json({ success: true, user: results[0] });
    });
});

// 🚨 CRITICAL 3: Remote Code Execution / Command Injection
app.get('/api/ping-host', (req, res) => {
    const host = req.query.host; // Untrusted user input
    
    // Developer tried to ping a host, but allowed Shell command injection
    exec(`ping -c 4 ${host}`, (err, stdout, stderr) => {
        if (err) return res.status(500).send(err.message);
        res.send(stdout);
    });
});

// 🚨 CRITICAL 4: Path Traversal (Arbitrary File Read)
app.get('/api/read-template', (req, res) => {
    const fileName = req.query.file; // e.g., "../../etc/passwd"
    
    fs.readFile(`/var/www/templates/${fileName}`, 'utf8', (err, data) => {
        if (err) return res.status(500).send("File not found");
        res.send(data);
    });
});

// 🚨 WARNING 5: Insecure direct object references (IDOR)
app.get('/api/user-profile', (req, res) => {
    const userId = req.query.id; // Directly trusts the query parameter without auth checks
    const query = `SELECT id, email, address FROM profiles WHERE id = ${userId}`;
    
    connection.query(query, (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results[0]);
    });
});

app.listen(3000, () => console.log('Server running on port 3000'));