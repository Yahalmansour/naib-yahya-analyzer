// Shared test setup: an in-process Postgres (PGlite) with the real migrations applied, plus an in-memory media store.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { drizzle } from 'drizzle-orm/pglite';
import { createApi } from '../server/api.ts';

const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../netlify/database/migrations');

export async function createTestDatabase() {
  const client = new PGlite();
  for (const entry of fs.readdirSync(migrationsDir).sort()) {
    const file = path.join(migrationsDir, entry, 'migration.sql');
    for (const statement of fs.readFileSync(file, 'utf8').split('--> statement-breakpoint')) {
      if (statement.trim()) await client.exec(statement);
    }
  }
  return { client, db: drizzle({ client }) };
}

export function createMemoryMediaStore() {
  const files = new Map();
  return {
    files,
    async set(key, data) {
      files.set(key, new Blob([data]));
    },
    async get(key) {
      return files.get(key) ?? null;
    },
    async delete(key) {
      files.delete(key);
    },
  };
}

export async function createTestApi(envValues = {}) {
  const { client, db } = await createTestDatabase();
  const media = createMemoryMediaStore();
  const env = {
    INITIAL_ADMIN_SETUP_KEY: 'test-only-initial-admin-key-long-enough',
    TOKEN_SECRET: 'test-only-token-secret-long-enough-0123',
    ...envValues,
  };
  const handle = createApi({ db, media, env: { get: (name) => env[name] } });
  const request = (url, options = {}, ip = '203.0.113.10') =>
    handle(new Request(`http://localhost${url}`, options), ip);
  return { client, db, media, handle, request, close: () => client.close() };
}

export const authHeaders = (token) => ({ Authorization: ['Bearer', token].join(' ') });
export const json = (method, body, token) => ({
  method,
  headers: { 'Content-Type': 'application/json', ...(token ? authHeaders(token) : {}) },
  body: JSON.stringify(body),
});
export const PNG_BYTES = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
  'base64',
);
export const pngFile = (name = 'photo.png') => new File([PNG_BYTES], name, { type: 'image/png' });
