const express = require('express');
const cors = require('cors');
const proxyHandler = require('./api/proxy.js');
const adminConfigRoutes = require('./api/adminConfig.js');
const { router: authRoutes } = require('./api/auth.js');

const app = express();
const port = process.env.PORT || 8006;

// Enable CORS for all routes
app.use(cors());
// Parse JSON bodies
app.use(express.json({ limit: '1mb' }));

// Serve the proxy endpoint
app.all('/api/proxy', proxyHandler);
app.all('/proxy', proxyHandler);

// Admin config API
app.use('/api', authRoutes);
app.use('/api', adminConfigRoutes);

// Serve static files from the root directory
app.use(express.static('.'));

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});