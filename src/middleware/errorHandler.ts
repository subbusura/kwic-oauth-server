import { Request, Response, NextFunction } from 'express';
import logger from '../lib/logger';

export default function errorHandler(err: any, req: Request, res: Response, _next: NextFunction) {
  logger.error('Request failed', {
    path: req.originalUrl,
    message: err?.message,
    stack: err?.stack
  });
  const status = err.status || 500;
  const message = err.message || 'Internal Server Error';
  res.status(status).json({ error: message });
}
