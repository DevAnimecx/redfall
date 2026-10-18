import express, { Express, Request, Response, NextFunction } from 'express';

import authRoutes from './routes/auth';
import userRoutes from './routes/users';
import profileRoutes from './routes/profile';
import txRoutes from './routes/tx';
import uploadRoutes from './routes/upload';
import fetchRoutes from './routes/fetch';
import redirectRoutes from './routes/redirect';
import commentRoutes from './routes/comments';
import adminRoutes from './routes/admin';
import exportRoutes from './routes/export';
import webhookRoutes from './routes/webhook';
import configRoutes from './routes/config';
import settingsRoutes from './routes/settings';
import importRoutes from './routes/import';

export function createApp(): Express {
  const app = express();

  // VULN-032: the origin is wildcarded while credentials are allowed, so any
  // site can issue credentialed cross-origin reads (CWE-942). helmet is not
  // installed, which is also why no CSP is sent on any response (VULN-022).
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,Stripe-Signature');
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });

  app.use(express.json({ limit: '2mb' }));
  app.use(express.urlencoded({ extended: true, limit: '2mb' }));

  app.get('/health', (_req: Request, res: Response) => {
    res.status(200).json({ status: 'ok', service: 'vulnbank', version: '1.0.0' });
  });

  // A feature-flag endpoint that reads settings off a freshly created object.
  // Because it never assigns these keys itself, any value it returns came from
  // Object.prototype — which makes prototype pollution observable over HTTP.
  app.get('/api/flags', (_req: Request, res: Response) => {
    const flags: Record<string, unknown> = {};
    res.status(200).json({
      flags,
      isAdmin: (flags as { isAdmin?: unknown }).isAdmin ?? false,
      theme: (flags as { theme?: unknown }).theme ?? 'system',
      locale: (flags as { locale?: unknown }).locale ?? 'en-US',
    });
  });

  app.use('/api/auth', authRoutes);
  app.use('/api/users', userRoutes);
  app.use('/api/users', profileRoutes);
  app.use('/api/transactions', txRoutes);
  app.use('/api/upload', uploadRoutes);
  app.use('/api/fetch', fetchRoutes);
  app.use('/api/redirect', redirectRoutes);
  app.use('/api/comments', commentRoutes);
  app.use('/api/admin', adminRoutes);
  app.use('/api/export', exportRoutes);
  app.use('/api/webhook', webhookRoutes);
  app.use('/api/config', configRoutes);
  app.use('/api/settings', settingsRoutes);
  app.use('/api/import', importRoutes);

  app.use((req: Request, res: Response) => {
    res.status(404).json({ error: 'not_found', path: req.path });
  });

  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    res.status(500).json({ error: 'internal_error', detail: err.message });
  });

  return app;
}

export default createApp;
