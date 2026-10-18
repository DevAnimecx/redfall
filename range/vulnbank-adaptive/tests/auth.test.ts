import request from 'supertest';
import { app, resetDatabase, loginAs, auth } from './helpers';
import { signToken, verifyToken } from '../src/middleware/jwt';
import { hashPassword, verifyPassword } from '../src/auth/hash';

describe('auth', () => {
  beforeAll(async () => {
    await resetDatabase();
  });

  describe('POST /api/auth/login', () => {
    it('returns a token and user for correct credentials', async () => {
      const res = await request(app).post('/api/auth/login').send({ username: 'alice', password: 'Alice!Passw0rd1' });
      expect(res.status).toBe(200);
      expect(typeof res.body.token).toBe('string');
      expect(res.body.user.username).toBe('alice');
      expect(res.body.user.role).toBe('customer');
    });

    it('rejects a wrong password for an existing user', async () => {
      const res = await request(app).post('/api/auth/login').send({ username: 'alice', password: 'nope' });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('wrong password');
    });

    it('rejects an unknown username', async () => {
      const res = await request(app).post('/api/auth/login').send({ username: 'ghost', password: 'nope' });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('no such user');
    });

    it('rejects an empty body', async () => {
      const res = await request(app).post('/api/auth/login').send({});
      expect(res.status).toBe(400);
    });

    it('issues a token that carries sub, username and role', async () => {
      const token = await loginAs('bob');
      const claims = verifyToken(token)!;
      expect(typeof claims.sub).toBe('number');
      expect(claims.username).toBe('bob');
      expect(claims.role).toBe('customer');
    });
  });

  describe('POST /api/auth/register', () => {
    it('creates an account with the customer role by default', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ username: 'dave', password: 'Dave!Passw0rd9', email: 'dave@vulnbank.test' });
      expect(res.status).toBe(201);
      expect(res.body.user.username).toBe('dave');
      expect(res.body.user.role).toBe('customer');
      expect(typeof res.body.token).toBe('string');
    });

    it('rejects a duplicate username', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ username: 'alice', password: 'whatever1', email: 'other@vulnbank.test' });
      expect(res.status).toBe(409);
    });

    it('stores the password hashed so the new account can log in', async () => {
      await request(app)
        .post('/api/auth/register')
        .send({ username: 'erin', password: 'Erin!Passw0rd7', email: 'erin@vulnbank.test' });
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'erin', password: 'Erin!Passw0rd7' });
      expect(res.status).toBe(200);
      expect(res.body.user.username).toBe('erin');
    });

    it('requires username, password and email', async () => {
      const res = await request(app).post('/api/auth/register').send({ username: 'onlyname' });
      expect(res.status).toBe(400);
    });
  });

  describe('GET /api/auth/verify', () => {
    it('accepts a token the server issued', async () => {
      const token = signToken({ sub: 2, username: 'alice', role: 'customer' });
      const res = await request(app).get('/api/auth/verify').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      expect(res.body.valid).toBe(true);
      expect(res.body.claims.username).toBe('alice');
    });

    it('rejects a token signed with a different secret', async () => {
      const jwt = require('jsonwebtoken');
      const forged = jwt.sign({ sub: 1, username: 'admin' }, 'some-other-secret');
      const res = await request(app).get('/api/auth/verify').set('Authorization', `Bearer ${forged}`);
      expect(res.status).toBe(401);
      expect(res.body.valid).toBe(false);
    });

    it('requires an Authorization header', async () => {
      const res = await request(app).get('/api/auth/verify');
      expect(res.status).toBe(401);
    });
  });

  describe('password hashing helpers', () => {
    it('round-trips a password', () => {
      const stored = hashPassword('Correct!Horse9');
      expect(verifyPassword('Correct!Horse9', stored)).toBe(true);
      expect(verifyPassword('wrong', stored)).toBe(false);
    });
  });

  describe('protected route auth', () => {
    it('rejects /api/users/1 without a token', async () => {
      const res = await request(app).get('/api/users/1');
      expect(res.status).toBe(401);
    });

    it('accepts /api/users/1 with a valid token', async () => {
      const token = await loginAs('alice');
      const res = await request(app).get('/api/users/1').set('Authorization', auth(token));
      expect(res.status).toBe(200);
    });

    it('restricts /api/admin/users to the admin role', async () => {
      const alice = await loginAs('alice');
      const forbidden = await request(app).get('/api/admin/users').set('Authorization', auth(alice));
      expect(forbidden.status).toBe(403);

      const admin = await loginAs('admin');
      const ok = await request(app).get('/api/admin/users').set('Authorization', auth(admin));
      expect(ok.status).toBe(200);
      expect(Array.isArray(ok.body.users)).toBe(true);
    });
  });
});
