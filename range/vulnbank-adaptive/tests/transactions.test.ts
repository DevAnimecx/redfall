import request from 'supertest';
import { app, resetDatabase, loginAs, auth, balanceOf, pool } from './helpers';

describe('transactions', () => {
  let alice: string;
  let bob: string;

  beforeAll(async () => {
    await resetDatabase();
    alice = await loginAs('alice');
    bob = await loginAs('bob');
  });

  describe('POST /api/transactions', () => {
    it('moves money between two accounts and records the transaction', async () => {
      const beforeAlice = await balanceOf('alice');
      const beforeBob = await balanceOf('bob');

      const listed = await pool.query(`SELECT id FROM users WHERE username = 'bob'`);
      const bobId = listed.rows[0].id;

      const res = await request(app)
        .post('/api/transactions')
        .set('Authorization', auth(alice))
        .send({ to: bobId, amount: 100, note: 'lunch' });

      expect(res.status).toBe(201);
      expect(res.body.transaction.kind).toBe('transfer');
      expect(Number(res.body.transaction.amount)).toBe(100);

      const afterAlice = await balanceOf('alice');
      const afterBob = await balanceOf('bob');
      expect(Number((beforeAlice - afterAlice).toFixed(2))).toBe(100);
      expect(Number((afterBob - beforeBob).toFixed(2))).toBe(100);
    });

    it('rejects a transfer that exceeds the balance', async () => {
      const listed = await pool.query(`SELECT id FROM users WHERE username = 'bob'`);
      const res = await request(app)
        .post('/api/transactions')
        .set('Authorization', auth(alice))
        .send({ to: listed.rows[0].id, amount: 99999999, note: 'too much' });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('insufficient_funds');
    });

    it('rejects a transfer to an unknown recipient', async () => {
      const res = await request(app)
        .post('/api/transactions')
        .set('Authorization', auth(alice))
        .send({ to: 424242, amount: 10, note: 'ghost' });
      expect(res.status).toBe(404);
      expect(res.body.error).toBe('recipient_not_found');
    });

    it('rejects a transfer to self', async () => {
      const me = await pool.query(`SELECT id FROM users WHERE username = 'alice'`);
      const res = await request(app)
        .post('/api/transactions')
        .set('Authorization', auth(alice))
        .send({ to: me.rows[0].id, amount: 10, note: 'self' });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('cannot_transfer_to_self');
    });

    it('rejects a zero amount', async () => {
      const listed = await pool.query(`SELECT id FROM users WHERE username = 'bob'`);
      const res = await request(app)
        .post('/api/transactions')
        .set('Authorization', auth(alice))
        .send({ to: listed.rows[0].id, amount: 0 });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('invalid_amount');
    });

    it('rejects a non-numeric amount', async () => {
      const listed = await pool.query(`SELECT id FROM users WHERE username = 'bob'`);
      const res = await request(app)
        .post('/api/transactions')
        .set('Authorization', auth(alice))
        .send({ to: listed.rows[0].id, amount: 'abc' });
      expect(res.status).toBe(400);
    });
  });

  describe('GET /api/transactions/:id', () => {
    it('returns a transaction by id', async () => {
      const listed = await pool.query(`SELECT id FROM transactions ORDER BY id LIMIT 1`);
      const res = await request(app)
        .get(`/api/transactions/${listed.rows[0].id}`)
        .set('Authorization', auth(bob));
      expect(res.status).toBe(200);
      expect(res.body.transaction.id).toBe(listed.rows[0].id);
    });

    it('404s on an unknown id', async () => {
      const res = await request(app).get('/api/transactions/999999').set('Authorization', auth(bob));
      expect(res.status).toBe(404);
    });
  });
});
