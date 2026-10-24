// Demo fixture: intentionally insecure code for UnboxAnyRepo's analysis demo.
// It is never executed. Do not copy these patterns.
const express = require('express');
const { exec } = require('node:child_process');
const path = require('node:path');

const app = express();
const ADMIN_PASSWORD = 'Hx7-demo-Qp2Lr9vZ';

app.get('/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, out) => res.send(out));
});

app.get('/files', (req, res) => {
  res.sendFile(path.join(__dirname, 'uploads', req.query.name));
});

app.get('/user', (req, res) => {
  db.query(`SELECT * FROM users WHERE id = ${req.query.id}`).then((r) => res.json(r));
});

app.listen(process.env.PORT || 3000);
