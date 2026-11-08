// Build step for Netlify: copies the static frontend to dist/ and enables skew protection.
//
// Skew protection keeps a browser that loaded an older deploy talking to that same deploy's API and assets
// until it does a full page load, so long-lived sessions don't break when a new version is published.
// Netlify exposes a per-deploy token at build time; we embed it in the HTML, the frontend sends it with
// every API request, and .netlify/v1/skew-protection.json tells Netlify where to look for it.
// See https://docs.netlify.com/deploy/deploy-overview/#skew-protection
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const SKEW_HEADER = 'x-skew-token';
export const SKEW_QUERY = 'skew';
export const SKEW_META = 'netlify-skew-token';

export const skewProtectionConfig = {
  patterns: ['/api/.*', '.*\\.(js|css)$'],
  sources: [
    { type: 'header', name: SKEW_HEADER },
    { type: 'query', name: SKEW_QUERY },
  ],
};

const escapeAttribute = (value) =>
  value.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');

/** Adds the token as a <meta> tag and pins same-origin script/stylesheet URLs to this deploy. */
export function injectSkewToken(html, token) {
  if (!token) return html;
  const encoded = encodeURIComponent(token);
  const pinned = html.replace(
    /(<(?:script|link)\b[^>]*?\s(?:src|href)=")(\/[^"?#]+\.(?:js|css))(")/g,
    (_match, before, url, after) => `${before}${url}?${SKEW_QUERY}=${encoded}${after}`,
  );
  const meta = `<meta name="${SKEW_META}" content="${escapeAttribute(token)}">`;
  return pinned.replace(/(<meta\s+charset=[^>]*>)/i, `$1\n    ${meta}`);
}

export async function build({ root, token }) {
  const publicDir = path.join(root, 'public');
  const distDir = path.join(root, 'dist');
  await fs.rm(distDir, { recursive: true, force: true });
  await fs.cp(publicDir, distDir, { recursive: true });

  const indexPath = path.join(distDir, 'index.html');
  await fs.writeFile(indexPath, injectSkewToken(await fs.readFile(indexPath, 'utf8'), token));

  const frameworksDir = path.join(root, '.netlify', 'v1');
  await fs.mkdir(frameworksDir, { recursive: true });
  await fs.writeFile(
    path.join(frameworksDir, 'skew-protection.json'),
    `${JSON.stringify(skewProtectionConfig, null, 2)}\n`,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const token = process.env.NETLIFY_SKEW_PROTECTION_TOKEN || '';
  await build({ root, token });
  console.log(
    token
      ? 'Built dist/ with skew protection enabled.'
      : 'Built dist/ (no NETLIFY_SKEW_PROTECTION_TOKEN available, so the skew token was not embedded).',
  );
}
