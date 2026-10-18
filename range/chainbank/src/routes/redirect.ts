import { Router } from 'express';

const router = Router();

/**
 * CHN-06, step A — open redirect with no host allow-list.
 *
 * On its own this is a phishing aid. Chained with `/api/oauth/authorize`, which
 * appends the access token to whatever redirect target it is given, it moves a
 * live session token to an attacker-controlled origin.
 */
router.get('/', (req, res) => {
  const url = String(req.query.url || '/');
  res.redirect(302, url);
});

export default router;
