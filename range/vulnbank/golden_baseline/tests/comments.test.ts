import request from 'supertest';
import { app, resetDatabase } from './helpers';

describe('comments', () => {
  beforeAll(async () => {
    await resetDatabase();
  });

  it('creates a comment without authentication', async () => {
    const res = await request(app)
      .post('/api/comments')
      .send({ body: 'Great service this month.', author: 'carol', account_id: 'general' });
    expect(res.status).toBe(201);
    expect(res.body.comment.body).toBe('Great service this month.');
    expect(res.body.comment.author).toBe('carol');
  });

  it('defaults the author to anonymous', async () => {
    const res = await request(app).post('/api/comments').send({ body: 'anonymous note' });
    expect(res.status).toBe(201);
    expect(res.body.comment.author).toBe('anonymous');
  });

  it('requires a body', async () => {
    const res = await request(app).post('/api/comments').send({ author: 'nobody' });
    expect(res.status).toBe(400);
  });

  it('lists comments for an account as HTML, newest first', async () => {
    const res = await request(app).get('/api/comments?account_id=general');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('html');
    expect(res.text).toContain('Great service this month.');
    const newest = res.text.indexOf('Great service this month.');
    const seeded = res.text.indexOf('Welcome to the community board.');
    expect(newest).toBeLessThan(seeded);
  });

  it('returns an empty board for an unknown account', async () => {
    const res = await request(app).get('/api/comments?account_id=nothing-here');
    expect(res.status).toBe(200);
    expect(res.text).toContain('<ul></ul>');
  });
});
