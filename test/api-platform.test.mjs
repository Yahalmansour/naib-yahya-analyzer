import assert from 'node:assert/strict';
import { test } from 'node:test';
import { MAX_FILE_SIZE } from '../server/api.ts';
import { authHeaders, createTestApi, json, pngFile } from './helpers.mjs';

async function setupAdmin(request) {
  const response = await request('/api/auth/register', json('POST', {
    username: 'Site Owner',
    ownerLoginId: 'private-owner-22',
    setupKey: 'test-only-initial-admin-key-long-enough',
    password: 'very-long-test-password',
  }));
  assert.equal(response.status, 201);
  return response.json();
}

test('failed sign-ins are limited per client IP and successful ones are not counted', async (t) => {
  const api = await createTestApi();
  t.after(() => api.close());
  await setupAdmin(api.request);
  const login = (password, ip) =>
    api.request('/api/auth/login', json('POST', { loginId: 'private-owner-22', password }), ip);

  for (let i = 0; i < 5; i += 1) assert.equal((await login('very-long-test-password', '198.51.100.1')).status, 200);
  for (let i = 0; i < 10; i += 1) assert.equal((await login('wrong-password', '198.51.100.1')).status, 401);
  assert.equal((await login('very-long-test-password', '198.51.100.1')).status, 429);
  assert.equal((await login('very-long-test-password', '198.51.100.2')).status, 200);
});

test('generates and persists a session signing key when TOKEN_SECRET is not configured', async (t) => {
  const api = await createTestApi({ TOKEN_SECRET: undefined });
  t.after(() => api.close());
  const admin = await setupAdmin(api.request);
  const stored = await api.client.query("SELECT value FROM app_secrets WHERE name = 'token_secret'");
  assert.equal(stored.rows.length, 1);
  assert.ok(stored.rows[0].value.length >= 64);

  // A second API instance (another function instance / cold start) accepts the same token.
  const { createApi } = await import('../server/api.ts');
  const other = createApi({ db: api.db, media: api.media, env: { get: () => undefined } });
  const me = await other(new Request('http://localhost/api/auth/me', { headers: authHeaders(admin.token) }));
  assert.equal(me.status, 200);
  assert.equal((await me.json()).role, 'admin');
});

test('first-account setup is unavailable without INITIAL_ADMIN_SETUP_KEY', async (t) => {
  const api = await createTestApi({ INITIAL_ADMIN_SETUP_KEY: undefined });
  t.after(() => api.close());
  const response = await api.request('/api/auth/register', json('POST', {
    username: 'Site Owner', ownerLoginId: 'private-owner-22', setupKey: 'x', password: 'very-long-test-password',
  }));
  assert.equal(response.status, 503);
});

test('API responses carry security headers, unknown routes 404, and uploads respect the function size limit', async (t) => {
  const api = await createTestApi();
  t.after(() => api.close());
  const admin = await setupAdmin(api.request);

  const status = await api.request('/api/auth/status');
  assert.match(status.headers.get('content-security-policy'), /img-src 'self' data: blob:;/);
  assert.equal(status.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(status.headers.get('cache-control'), 'no-store');
  assert.equal((await api.request('/api/unknown', { headers: authHeaders(admin.token) })).status, 404);
  assert.equal((await api.request('/api/documents/not-a-number', { headers: authHeaders(admin.token) })).status, 404);

  const large = new FormData();
  large.append('file', new File([new Uint8Array(MAX_FILE_SIZE + 1)], 'large.pdf', { type: 'application/pdf' }));
  const tooLarge = await api.request('/api/media', { method: 'POST', headers: authHeaders(admin.token), body: large });
  assert.equal(tooLarge.status, 400);
  assert.match((await tooLarge.json()).error, /4 ميجابايت/);
  assert.equal(api.media.files.size, 0);

  // Browsers send an empty file part when an optional photo is left blank; that must not be treated as an upload.
  const procedure = new FormData();
  procedure.append('title', 'جولة مسائية');
  procedure.append('category', 'جولة تفقدية');
  procedure.append('details', 'لا ملاحظات.');
  procedure.append('procedurePhoto', new File([], '', { type: 'application/octet-stream' }));
  const created = await api.request('/api/security/procedures', { method: 'POST', headers: authHeaders(admin.token), body: procedure });
  assert.equal(created.status, 201);
  assert.equal((await created.json()).media_id, null);

  const upload = new FormData();
  upload.append('file', pngFile('صورة.png'));
  const media = await (await api.request('/api/media', { method: 'POST', headers: authHeaders(admin.token), body: upload })).json();
  const download = await api.request(`/api/media/${media.id}`, { headers: authHeaders(admin.token) });
  assert.equal(download.status, 200);
  assert.match(download.headers.get('content-disposition'), /filename\*=UTF-8''%D8%B5/);
  assert.equal((await api.request(`/api/media/${media.id}`, { method: 'DELETE', headers: authHeaders(admin.token) })).status, 204);
  assert.equal(api.media.files.size, 0);
});

test('rolls back the stored file when the database insert fails', async (t) => {
  const api = await createTestApi();
  t.after(() => api.close());
  const admin = await setupAdmin(api.request);
  const permit = (number) => {
    const form = new FormData();
    for (const [key, value] of Object.entries({
      permitNumber: number, vehiclePlate: 'ABC 123', driverName: 'سائق', identityNumber: 'ID-1', phone: '0500000000',
      purpose: 'توريد', validFrom: '2026-01-01', validUntil: '2026-12-31',
    })) form.append(key, value);
    form.append('permitPhoto', pngFile('permit.png'));
    return api.request('/api/security/permits', { method: 'POST', headers: authHeaders(admin.token), body: form });
  };
  assert.equal((await permit('VP-1')).status, 201);
  assert.equal((await permit('VP-1')).status, 409);
  assert.equal(api.media.files.size, 1);
});
