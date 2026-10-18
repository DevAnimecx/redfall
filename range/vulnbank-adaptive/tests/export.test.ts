import request from 'supertest';
import { app, resetDatabase, loginAs, auth } from './helpers';

describe('export', () => {
  let token: string;

  beforeAll(async () => {
    await resetDatabase();
    token = await loginAs('alice');
  });

  it('streams a CSV with a header row and one row per transaction', async () => {
    const res = await request(app).get('/api/export').set('Authorization', auth(token));
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/csv');
    expect(res.headers['content-disposition']).toContain('transactions.csv');

    const lines = res.text.trim().split('\n');
    expect(lines[0]).toBe('id,owner,username,kind,counterparty,amount,note');
    expect(lines.length).toBeGreaterThanOrEqual(5);
    expect(lines[1].split(',').length).toBe(7);
  });

  it('requires authentication', async () => {
    const res = await request(app).get('/api/export');
    expect(res.status).toBe(401);
  });
});
