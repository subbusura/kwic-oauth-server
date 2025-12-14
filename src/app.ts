import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import compression from 'compression';
import path from 'path';
import oauthRoutes from './routes/oauth';
import adminRoutes from './routes/admin';
import accountRoutes from './routes/account';
import authRoutes from './routes/auth';
import adminPortalRoutes from './routes/adminPortal';
import errorHandler from './middleware/errorHandler';
import { connectDatastores } from './config';
import cookieParser from 'cookie-parser';
import ServiceProvider from './models/ServiceProvider';

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));
app.use('/static', express.static(path.join(__dirname, '../public')));

// Dynamic CSP middleware that allows form submissions to registered SPs
app.use(async (req, res, next) => {
  if (req.path.startsWith('/auth')) {
    if (req.path.startsWith('/auth/idp/sso')) {
      try {
        const sps = await ServiceProvider.find({}, 'acs_url');
        const allowedDomains = sps
          .map((sp) => {
            try {
              const url = new URL(sp.acs_url);
              return url.origin;
            } catch {
              return null;
            }
          })
          .filter((d): d is string => d !== null);

        helmet({
          contentSecurityPolicy: {
            directives: {
              ...helmet.contentSecurityPolicy.getDefaultDirectives(),
              'script-src': ["'self'", "'unsafe-inline'"],
              'form-action': ["'self'", ...allowedDomains]
            }
          }
        })(req, res, next);
      } catch (err) {
        next();
      }
    } else {
      helmet({
        contentSecurityPolicy: {
          directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            'script-src': ["'self'", "'unsafe-inline'"]
          }
        }
      })(req, res, next);
    }
  } else {
    helmet()(req, res, next);
  }
});

app.use(
  cors({
    origin: true,
    credentials: true
  })
);
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(compression());
app.use(morgan('combined'));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/oauth', limiter);
app.use('/admin', limiter);

connectDatastores();

app.use('/.well-known', oauthRoutes);
app.use('/oauth', oauthRoutes);
app.use('/accounts', accountRoutes);
app.use('/auth', authRoutes);
app.use('/admin', adminRoutes);
app.use('/admin-ui', adminPortalRoutes);

// convenience redirects so /accounts* go through auth router

// app.get('/accounts/:userId/:section', (req, res) =>
//   res.redirect(
//     `/accounts/${encodeURIComponent(req.params.userId)}/${encodeURIComponent(req.params.section)}`
//   )
// );

// default landing: if logged in, go to accounts/general, else login
app.get('/', (req, res) => {
  const uid = (req as any).cookies?.uid;
  if (uid) return res.redirect(`/accounts/${encodeURIComponent(uid)}/general`);
  return res.redirect('/auth/login');
});

app.use(errorHandler);

export default app;
