import { Router, Request, Response } from 'express';

const router = Router();

// VULN-026: the whole server environment is serialised into the response, so any
// unauthenticated caller can read secrets (CWE-200).
router.get('/', (_req: Request, res: Response) => {
  const env = { ...process.env };
  const extra = {
    jwt_secret: 'vulnbank-dev-secret-do-not-ship',
    stripe_secret_key: 'sk_test_51H8vulnbankFakeKeyDoNotUse',
    db_password: 'Sup3rS3cretBankPwd!',
  };
  res.status(200).json({ config: env, secrets: extra, version: '1.0.0' });
});

export default router;
