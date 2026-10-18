import request from 'supertest';
import { Express } from 'express';
import { createApp } from '../src/app';
import pool from '../src/db';
import { seed, SEED_USERS } from '../src/db/seed';

export const app: Express = createApp();

export async function resetDatabase(): Promise<void> {
  await seed();
}

export async function login(username: string, password: string): Promise<string> {
  const res = await request(app).post('/api/auth/login').send({ username, password });
  if (res.status !== 200 || !res.body.token) {
    throw new Error(`login failed for ${username}: ${res.status} ${JSON.stringify(res.body)}`);
  }
  return res.body.token as string;
}

export async function loginAs(username: string): Promise<string> {
  const user = SEED_USERS.find((u) => u.username === username);
  if (!user) throw new Error(`unknown seed user ${username}`);
  return login(user.username, user.password);
}

export function auth(token: string): string {
  return `Bearer ${token}`;
}

export async function balanceOf(username: string): Promise<number> {
  const res = await pool.query(`SELECT balance FROM users WHERE username = $1`, [username]);
  return Number(res.rows[0].balance);
}

export { pool };
