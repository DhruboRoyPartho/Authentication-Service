const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const authRoutes = require('./routes/auth');
const { connectDB } = require('./config');

const createApp = async (opts = {}) => {
  // opts.skipDBConnect = true allows tests to create the app without triggering connectDB
  if (!opts.skipDBConnect) await connectDB();
  const app = express();
  app.use(helmet());
  app.use(cors());
  app.use(express.json());
  app.use(morgan('dev'));

  app.use('/api/auth', authRoutes);

  app.get('/api/health', (req, res) => res.json({ ok: true }));

  // basic error handler
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(err.status || 500).json({ error: err.message || 'Internal' });
  });

  return app;
};

module.exports = { createApp };
