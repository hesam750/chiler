const express = require('express');
const cors = require('cors');
const proxyHandler = require('./api/proxy.js');

const app = express();
const port = process.env.PORT || 8006;

// Enable CORS for all routes
app.use(cors());

// Serve the proxy endpoint
app.all('/api/proxy', proxyHandler);
app.all('/proxy', proxyHandler);

// Serve static files from the root directory
app.use(express.static('.'));

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});