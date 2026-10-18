import request from 'supertest';
import { app, resetDatabase, loginAs, auth } from './helpers';

describe('admin', () => {
  let admin: string;
  let alice: string;

  beforeAll(async () => {
    await resetDatabase();
    admin = await loginAs('admin');
    alice = await loginAs('alice');
  });

  it('lists every account for an admin', async () => {
    const res = await request(app).get('/api/admin/users').set('Authorization', auth(admin));
    expect(res.status).toBe(200);
    const names = res.body.users.map((u: { username: string }) => u.username);
    expect(names).toEqual(expect.arrayContaining(['admin', 'alice', 'bob', 'carol']));
  });

  it('forbids a customer from the admin list', async () => {
    const res = await request(app).get('/api/admin/users').set('Authorization', auth(alice));
    expect(res.status).toBe(403);
  });

  it('requires a token for the admin list', async () => {
    const res = await request(app).get('/api/admin/users');
    expect(res.status).toBe(401);
  });

  it('runs a read-only SQL command through the exec endpoint', async () => {
    const res = await request(app)
      .post('/api/admin/exec')
      .set('Authorization', auth(admin))
      .send({ cmd: 'SELECT 1 AS ok' });
    expect(res.status).toBe(200);
    expect(res.body.stdout).toContain('1');
  });

  it('defaults the exec command to a row count for a table', async () => {
    const res = await request(app)
      .post('/api/admin/exec')
      .set('Authorization', auth(admin))
      .send({ table: 'users' });
    expect(res.status).toBe(200);
    expect(Number(res.body.stdout.trim())).toBeGreaterThanOrEqual(4);
  });

  it('forbids a customer from the exec endpoint', async () => {
    const res = await request(app)
      .post('/api/admin/exec')
      .set('Authorization', auth(alice))
      .send({ cmd: 'SELECT 1' });
    expect(res.status).toBe(403);
  });
});
