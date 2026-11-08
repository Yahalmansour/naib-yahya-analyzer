import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { build, injectSkewToken, skewProtectionConfig } from '../scripts/build.mjs';

const html = `<!doctype html>
<html><head>
    <meta charset="utf-8">
    <link rel="stylesheet" href="/styles.css">
    <script src="/app.js" defer></script>
</head><body></body></html>`;

test('embeds the deploy skew token and pins same-origin assets to the deploy', () => {
  const output = injectSkewToken(html, 'tok/en"<1>');
  assert.match(output, /<meta name="netlify-skew-token" content="tok\/en&quot;&lt;1&gt;">/);
  assert.match(output, /href="\/styles\.css\?skew=tok%2Fen%22%3C1%3E"/);
  assert.match(output, /src="\/app\.js\?skew=tok%2Fen%22%3C1%3E"/);
  assert.equal(injectSkewToken(html, ''), html);
});

test('the skew protection config covers the API and the assets, matching what the frontend sends', () => {
  const patterns = skewProtectionConfig.patterns.map((pattern) => new RegExp(`^${pattern}$`));
  for (const pathname of ['/api/auth/me', '/api/media/1/preview', '/app.js', '/styles.css']) {
    assert.ok(patterns.some((pattern) => pattern.test(pathname)), pathname);
  }
  assert.ok(!patterns.some((pattern) => pattern.test('/')));
  assert.deepEqual(skewProtectionConfig.sources, [
    { type: 'header', name: 'x-skew-token' },
    { type: 'query', name: 'skew' },
  ]);
  const frontend = fs.readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.match(frontend, /meta\[name="netlify-skew-token"\]/);
  assert.match(frontend, /headers\.set\('x-skew-token', skewToken\)/);
});

test('build writes dist/ and the Frameworks API skew-protection file', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'naib-build-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'public'));
  fs.writeFileSync(path.join(root, 'public', 'index.html'), html);
  fs.writeFileSync(path.join(root, 'public', 'app.js'), '');
  await build({ root, token: 'deploy-token' });
  assert.match(fs.readFileSync(path.join(root, 'dist', 'index.html'), 'utf8'), /content="deploy-token"/);
  assert.ok(fs.existsSync(path.join(root, 'dist', 'app.js')));
  const written = JSON.parse(fs.readFileSync(path.join(root, '.netlify', 'v1', 'skew-protection.json'), 'utf8'));
  assert.deepEqual(written, skewProtectionConfig);
});
