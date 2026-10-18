import request from 'supertest';
import { app, resetDatabase, balanceOf } from './helpers';

describe('stripe webhook', () => {
  beforeAll(async () => {
    await resetDatabase();
  });

  it('credits the customer named in a charge.succeeded event', async () => {
    const before = await balanceOf('bob');
    const res = await request(app)
      .post('/api/webhook/stripe')
      .send({ type: 'charge.succeeded', data: { object: { customer: 'bob', amount: 12345 } } });

    expect(res.status).toBe(200);
    expect(res.body.received).toBe(true);
    expect(Number(res.body.credited.balance) - before).toBeCloseTo(123.45, 2);
  });

  it('accepts an unrecognised event type and audits it', async () => {
    const res = await request(app).post('/api/webhook/stripe').send({ type: 'invoice.paid' });
    expect(res.status).toBe(200);
    expect(res.body.received).toBe(true);
  });

  it('requires an event type', async () => {
    const res = await request(app).post('/api/webhook/stripe').send({});
    expect(res.status).toBe(400);
  });

  it('404s when the customer does not exist', async () => {
    const res = await request(app)
      .post('/api/webhook/stripe')
      .send({ type: 'charge.succeeded', data: { object: { customer: 'ghost', amount: 100 } } });
    expect(res.status).toBe(404);
  });
});
