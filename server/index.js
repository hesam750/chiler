const express = require('express');
const path = require('path');
const proxy = require('./proxy');

const app = express();
app.use(express.urlencoded({ extended: false }));

const publicDir = path.join(__dirname, '..');
app.use(express.static(publicDir));

app.use('/proxy', (req, res) => proxy(req, res));
app.get('/', (req, res) => res.sendFile(path.join(publicDir, 'dashboard.html')));

const port = process.env.PORT || 8000;
app.listen(port);