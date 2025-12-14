import 'dotenv/config';
import http from 'http';
import app from './app';
import logger from './lib/logger';

const PORT = process.env.PORT || 4000;
const server = http.createServer(app);

server.listen(PORT, () => {
  logger.info(`Server listening on ${PORT}`);
});
