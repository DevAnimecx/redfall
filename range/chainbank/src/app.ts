import express, { Express } from 'express';
import cors from 'cors';

import accounts from './routes/accounts';
import admin from './routes/admin';
import auth from './routes/auth';
import debug from './routes/debug';
import documents from './routes/documents';
import internal from './routes/internal';
import me from './routes/me';
import oauth from './routes/oauth';
import plugins from './routes/plugins';
import preview from './routes/preview';
import redirect from './routes/redirect';
import search from './routes/search';

export function createApp(): Express {
  const app = express();
  app.disable('x-powered-by');
  app.use(cors());
  app.use(express.json({ limit: '2mb' }));
  app.use(express.urlencoded({ extended: true }));

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', app: 'chainbank', version: '0.1.1' });
  });

  app.use('/api/accounts', accounts);
  app.use('/api/admin', admin);
  app.use('/api/auth', auth);
  app.use('/api/debug', debug);
  app.use('/api/documents', documents);
  app.use('/api/internal', internal);
  app.use('/api/me', me);
  app.use('/api/oauth', oauth);
  app.use('/api/plugins', plugins);
  app.use('/api/preview', preview);
  app.use('/api/redirect', redirect);
  app.use('/api/search', search);

  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).json({ error: 'internal_error', detail: err.message });
  });

  return app;
}

export default createApp;
