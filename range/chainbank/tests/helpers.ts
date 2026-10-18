import { createApp } from '../src/app';
import pool from '../src/db';

export const app = createApp();

export async function login(username: string, password: string): Promise<string> {
  const res = await import('supertest').then((m) =>
    m.default(app).post('/api/auth/login').send({ username, password }),
  );
  return res.body.token;
}

export const db = pool;
