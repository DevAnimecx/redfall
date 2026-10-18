import request from 'supertest';
import http from 'http';
import { AddressInfo } from 'net';
import { app, resetDatabase, loginAs, auth } from './helpers';

describe('fetch proxy', () => {
  let token: string;
  let upstream: http.Server;
  let upstreamUrl: string;

  beforeAll(async () => {
    await resetDatabase();
    token = await loginAs('alice');
    upstream = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('upstream-ok');
    });
    await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
    upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}/`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  });

  it('proxies a reachable URL and returns the body', async () => {
    const res = await request(app).post('/api/fetch').set('Authorization', auth(token)).send({ url: upstreamUrl });
    expect(res.status).toBe(200);
    expect(res.body.status).toBe(200);
    expect(res.body.body).toBe('upstream-ok');
  });

  it('requires the url field', async () => {
    const res = await request(app).post('/api/fetch').set('Authorization', auth(token)).send({});
    expect(res.status).toBe(400);
  });

  it('reports an upstream failure as 502', async () => {
    const res = await request(app)
      .post('/api/fetch')
      .set('Authorization', auth(token))
      .send({ url: 'http://127.0.0.1:1/nope' });
    expect(res.status).toBe(502);
    expect(res.body.error).toBe('upstream_failed');
  });

  it('requires authentication', async () => {
    const res = await request(app).post('/api/fetch').send({ url: upstreamUrl });
    expect(res.status).toBe(401);
  });
});

describe('redirect', () => {
  it('issues a 302 to the requested target', async () => {
    const res = await request(app).get('/api/redirect?to=/health');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/health');
  });

  it('requires the to parameter', async () => {
    const res = await request(app).get('/api/redirect');
    expect(res.status).toBe(400);
  });
});
