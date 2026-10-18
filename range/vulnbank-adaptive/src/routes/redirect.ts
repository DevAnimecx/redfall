import { Router, Request, Response } from 'express';

const router = Router();

// VULN-020: `to` is passed straight to res.redirect with no allowlist, so any
// external site can be reached through a trusted vulnbank link (CWE-601).
router.get('/', (req: Request, res: Response) => {
  const to = typeof req.query.to === 'string' ? req.query.to : '';
  if (!to) {
    res.status(400).json({ error: 'query parameter "to" is required' });
    return;
  }
  res.redirect(302, to);
});

export default router;
