// src/cluster.js
const cluster = require('cluster');
const numCPUs = require('os').cpus().length;
const { createApp } = require('./app');

if (cluster.isMaster) {
  console.info(`Master ${process.pid} is running`);

  // Fork workers based on CPU count
  const workerCount = process.env.NODE_ENV === 'production' ? numCPUs : 2;
  
  for (let i = 0; i < workerCount; i++) {
    cluster.fork();
  }

  cluster.on('exit', (worker, code, signal) => {
    console.info(`Worker ${worker.process.pid} died. Restarting...`);
    cluster.fork();
  });
} else {
  // Workers can share any TCP connection
  const start = async () => {
    try {
      const app = await createApp();
      const port = process.env.PORT || 4000;
      
      app.listen(port, () => {
        console.info(`Worker ${process.pid} started on port ${port}`);
      });
    } catch (error) {
      console.error('Failed to start worker:', error);
      process.exit(1);
    }
  };

  start();
}