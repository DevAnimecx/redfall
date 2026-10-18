import request from 'supertest';
import { app, resetDatabase, loginAs, auth } from './helpers';

let token: string;

describe('app surface', () => {
  beforeAll(async () => {
    await resetDatabase();
    token = await loginAs('alice');
  });

  it('serves a health check', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.service).toBe('vulnbank');
  });

  it('404s unknown paths with a JSON body', async () => {
    const res = await request(app).get('/api/nope');
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('not_found');
  });

  it('answers CORS preflight with 204 and the allowed methods', async () => {
    const res = await request(app).options('/api/auth/login');
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-methods']).toContain('POST');
  });

  it('exposes the service config endpoint', async () => {
    const res = await request(app).get('/api/config');
    expect(res.status).toBe(200);
    expect(res.body.version).toBe('1.0.0');
    expect(typeof res.body.config).toBe('object');
  });
});

describe('settings', () => {
  it('round-trips a settings payload', async () => {
    const put = await request(app)
      .post('/api/settings')
      .set('Authorization', auth(token))
      .send({ theme: 'light', notifications: false });
    expect(put.status).toBe(200);
    expect(put.body.settings.theme).toBe('light');

    const get = await request(app).get('/api/settings').set('Authorization', auth(token));
    expect(get.status).toBe(200);
    expect(get.body.settings.theme).toBe('light');
  });

  it('merges into the existing payload rather than replacing it', async () => {
    await request(app).post('/api/settings').set('Authorization', auth(token)).send({ a: 1, nested: { x: 1 } });
    const res = await request(app).post('/api/settings').set('Authorization', auth(token)).send({ nested: { y: 2 } });
    expect(res.body.settings.nested.x).toBe(1);
    expect(res.body.settings.nested.y).toBe(2);
  });

  it('requires authentication', async () => {
    const res = await request(app).post('/api/settings').send({ theme: 'dark' });
    expect(res.status).toBe(401);
  });
});

describe('import', () => {
  it('restores a plain JSON batch', async () => {
    const res = await request(app)
      .post('/api/import')
      .set('Authorization', auth(token))
      .send({ batch: { rows: [{ id: 1, name: 'row-one' }] } });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.imported.rows[0].name).toBe('row-one');
  });

  it('requires a batch field', async () => {
    const res = await request(app).post('/api/import').set('Authorization', auth(token)).send({});
    expect(res.status).toBe(400);
  });

  it('requires authentication', async () => {
    const res = await request(app).post('/api/import').send({ batch: { a: 1 } });
    expect(res.status).toBe(401);
  });
});
