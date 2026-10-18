import request from 'supertest';
import { app, resetDatabase, loginAs, auth } from './helpers';

describe('profile', () => {
  let token: string;

  beforeAll(async () => {
    await resetDatabase();
    token = await loginAs('alice');
  });

  it('renders the seeded profile as HTML', async () => {
    const res = await request(app).get('/api/users/2/profile').set('Authorization', auth(token));
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('html');
    expect(res.text).toContain('Seed bio for alice');
  });

  it('stores and returns an updated bio', async () => {
    const put = await request(app)
      .put('/api/users/2/profile')
      .set('Authorization', auth(token))
      .send({ display_name: 'Alice A.', bio: 'New bio text', website: 'https://example.com' });
    expect(put.status).toBe(200);
    expect(put.body.ok).toBe(true);

    const get = await request(app).get('/api/users/2/profile').set('Authorization', auth(token));
    expect(get.text).toContain('New bio text');
  });

  it('creates an empty profile at registration and renders it', async () => {
    const reg = await request(app)
      .post('/api/auth/register')
      .send({ username: 'freshuser', password: 'Fresh!User1234', email: 'fresh@vulnbank.test' });
    expect(reg.status).toBe(201);
    const newId = reg.body.user.id;

    const res = await request(app).get(`/api/users/${newId}/profile`).set('Authorization', auth(token));
    expect(res.status).toBe(200);
    expect(res.text).toContain('freshuser');
  });

  it('404s for an id that has no profile row', async () => {
    const res = await request(app).get('/api/users/99999/profile').set('Authorization', auth(token));
    expect(res.status).toBe(404);
  });

  it('requires authentication', async () => {
    const res = await request(app).get('/api/users/2/profile');
    expect(res.status).toBe(401);
  });
});
