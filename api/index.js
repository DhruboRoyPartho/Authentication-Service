const { createApp } = require('../src/app');

let cachedApp = null;

// Create or reuse the Express app instance. This avoids cold-start re-creating app on every invocation.
const getApp = async () => {
  if (!cachedApp) {
    // createApp will call connectDB which checks mongoose.readyState.
    cachedApp = await createApp();
  }
  return cachedApp;
};

// Vercel (and many Node serverless platforms) call the exported function with (req, res).
// Express apps are callable functions (app(req,res)), so we create the app once and forward requests.
module.exports = async (req, res) => {
  try {
    const app = await getApp();
    return app(req, res);
  } catch (err) {
    console.error('Serverless handler error:', err);
    res.statusCode = 500;
    res.end('Internal Server Error');
  }
};
