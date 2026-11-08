import type { Config, Context } from '@netlify/functions';
import { getStore } from '@netlify/blobs';
import { getDb } from '../../db/index.ts';
import { createApi, type MediaStore } from '../../server/api.ts';
import type { Database } from '../../server/db-helpers.ts';

let handle: ReturnType<typeof createApi> | undefined;

function getHandler() {
  if (!handle) {
    // Strong consistency so a file can be previewed immediately after it is uploaded.
    const store = getStore({ name: 'media', consistency: 'strong' });
    const media: MediaStore = {
      set: async (key, data) => {
        await store.set(key, data);
      },
      get: (key) => store.get(key, { type: 'blob' }),
      delete: (key) => store.delete(key),
    };
    handle = createApi({ db: getDb() as unknown as Database, media, env: Netlify.env });
  }
  return handle;
}

export default async (req: Request, context: Context) => getHandler()(req, context.ip);

export const config: Config = {
  path: '/api/*',
  // Same budget as the previous Express limiter: 300 API requests per minute per client IP.
  rateLimit: {
    windowLimit: 300,
    windowSize: 60,
    aggregateBy: ['ip', 'domain'],
  },
};
