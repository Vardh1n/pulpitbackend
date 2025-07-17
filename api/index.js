// This file is needed for Vercel serverless functions

// Re-export your Express app
const app = require('../index.js');
module.exports = app;