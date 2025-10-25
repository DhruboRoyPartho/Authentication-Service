const { createApp } = require('./app');
const config = require('./config');

const PORT = process.env.PORT || 4000;

(async () => {
  try {
    const app = await createApp();
    app.listen(PORT, () => console.log(`Auth service listening on port ${PORT}`));
  } catch (err) {
    console.error('Failed to start server', err);
    process.exit(1);
  }
})();
