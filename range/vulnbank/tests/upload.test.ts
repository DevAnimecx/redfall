import request from 'supertest';
import fs from 'fs';
import path from 'path';
import { app, resetDatabase, loginAs, auth } from './helpers';
import { UPLOAD_DIR } from '../src/routes/upload';

describe('upload', () => {
  let token: string;

  beforeAll(async () => {
    await resetDatabase();
    token = await loginAs('alice');
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  });

  it('stores an uploaded file and records it', async () => {
    const res = await request(app)
      .post('/api/upload')
      .set('Authorization', auth(token))
      .attach('file', Buffer.from('statement contents'), 'statement.txt');

    expect(res.status).toBe(201);
    expect(res.body.file.original).toBe('statement.txt');
    expect(res.body.file.size).toBe(18);
    expect(fs.existsSync(path.join(UPLOAD_DIR, 'statement.txt'))).toBe(true);
    expect(fs.readFileSync(path.join(UPLOAD_DIR, 'statement.txt'), 'utf8')).toBe('statement contents');
  });

  it('rejects a request with no file field', async () => {
    const res = await request(app).post('/api/upload').set('Authorization', auth(token)).field('nothing', '1');
    expect(res.status).toBe(400);
  });

  it('returns file metadata by id', async () => {
    const up = await request(app)
      .post('/api/upload')
      .set('Authorization', auth(token))
      .attach('file', Buffer.from('pdf-ish'), 'invoice.pdf');
    const id = up.body.file.id;

    const res = await request(app).get(`/api/upload/${id}`).set('Authorization', auth(token));
    expect(res.status).toBe(200);
    expect(res.body.file.original).toBe('invoice.pdf');
  });

  it('404s on an unknown file id', async () => {
    const res = await request(app).get('/api/upload/999999').set('Authorization', auth(token));
    expect(res.status).toBe(404);
  });

  it('requires authentication', async () => {
    const res = await request(app).post('/api/upload').attach('file', Buffer.from('x'), 'x.txt');
    expect(res.status).toBe(401);
  });
});
