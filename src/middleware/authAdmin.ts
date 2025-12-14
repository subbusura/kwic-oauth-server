import { Request, Response, NextFunction } from 'express';

export default function authAdmin(req: Request, res: Response, next: NextFunction) {
  const token = req.headers['x-admin-token'] || req.headers.authorization?.replace('Bearer ', '');
  if (!token || token !== process.env.ADMIN_SECRET_TOKEN) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  return next();
}
