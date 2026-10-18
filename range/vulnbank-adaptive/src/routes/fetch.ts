import { Router, Request, Response } from 'express';
import fetch from 'node-fetch';
import { requireAuth } from '../middleware/jwt';

const router = Router();

interface FetchBody {
  url?: unknown;
}

// VULN-018 / VULN-019: the caller-supplied URL is requested server-side with no
// scheme, host, or IP checks. Nothing blocks loopback, link-local, or the cloud
// metadata addresses, so this is a full SSRF including metadata theft (CWE-918).
router.post('/', requireAuth, async (req: Request, res: Response) => {
  const body = (req.body || {}) as FetchBody;
  const url = typeof body.url === 'string' ? body.url : '';

  if (!url) {
    res.status(400).json({ error: 'url is required' });
    return;
  }

  try {
    const upstream = await fetch(url, { timeout: 8000 });
    const text = await upstream.text();
    res.status(200).json({
      status: upstream.status,
      contentType: upstream.headers.get('content-type'),
      body: text.slice(0, 4000),
    });
  } catch (err) {
    res.status(502).json({ error: 'upstream_failed', detail: (err as Error).message, url });
  }
});

export default router;
