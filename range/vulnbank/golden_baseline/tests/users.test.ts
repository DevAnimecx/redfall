import request from 'supertest';
import { app, resetDatabase, loginAs, auth } from './helpers';

describe('users', () => {
  let token: string;

  beforeAll(async () => {
    await resetDatabase();
    token = await loginAs('alice');
  });

  describe('GET /api/users/:id', () => {
    it('returns the requested user', async () => {
      const res = await request(app).get('/api/users/1').set('Authorization', auth(token));
      expect(res.status).toBe(200);
      expect(res.body.user.username).toBe('admin');
      expect(res.body.user.email).toBe('admin@vulnbank.test');
    });

    it('404s on an unknown id', async () => {
      const res = await request(app).get('/api/users/99999').set('Authorization', auth(token));
      expect(res.status).toBe(404);
    });

    it('400s on a non-numeric id', async () => {
      const res = await request(app).get('/api/users/abc').set('Authorization', auth(token));
      expect(res.status).toBe(400);
    });
  });

  describe('GET /api/users', () => {
    it('lists users with the default page size', async () => {
      const res = await request(app).get('/api/users').set('Authorization', auth(token));
      expect(res.status).toBe(200);
      expect(res.body.limit).toBe(25);
      expect(res.body.count).toBeGreaterThanOrEqual(4);
    });

    it('honours an explicit limit', async () => {
      const res = await request(app).get('/api/users?limit=2').set('Authorization', auth(token));
      expect(res.status).toBe(200);
      expect(res.body.count).toBe(2);
    });

    it('rejects a negative limit', async () => {
      const res = await request(app).get('/api/users?limit=-5').set('Authorization', auth(token));
      expect(res.status).toBe(400);
    });
  });

  describe('GET /api/users/search', () => {
    it('finds a user by substring', async () => {
      const res = await request(app).get('/api/users/search?q=ali').set('Authorization', auth(token));
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('html');
      expect(res.text).toContain('alice');
    });

    it('requires the q parameter', async () => {
      const res = await request(app).get('/api/users/search').set('Authorization', auth(token));
      expect(res.status).toBe(400);
    });

    it('reports zero matches for an unknown term', async () => {
      const res = await request(app).get('/api/users/search?q=zzzzz').set('Authorization', auth(token));
      expect(res.status).toBe(200);
      expect(res.text).toContain('0 match(es)');
    });
  });
});
