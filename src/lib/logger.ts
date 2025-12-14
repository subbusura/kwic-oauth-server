import winston from 'winston';

const logLevel = process.env.LOG_LEVEL || 'debug';

const levels = {
  error: 0,
  warn: 1,
  info: 2,
  audit: 3,
  debug: 4
};

const baseLogger = winston.createLogger({
  levels,
  level: logLevel,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()]
});

// Helper to log audit events in a consistent way
const logger = Object.assign(baseLogger, {
  audit: (message: string, meta?: Record<string, unknown>) => {
    baseLogger.log('audit', message, meta);
  }
});

export default logger;
