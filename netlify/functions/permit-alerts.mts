import type { Config } from '@netlify/functions';
import { getDb } from '../../db/index.ts';
import type { Database } from '../../server/db-helpers.ts';
import { createPermitAlertRunner, createWhatsAppSender } from '../../server/permit-alerts.ts';

// Checks vehicle permits every hour and sends WhatsApp alerts when WHATSAPP_* variables are configured.
export default async () => {
  const run = createPermitAlertRunner({
    db: getDb() as unknown as Database,
    sendAlert: createWhatsAppSender(Netlify.env.toObject()),
  });
  const result = await run();
  console.log('WhatsApp permit alert run:', JSON.stringify(result));
};

export const config: Config = {
  schedule: '@hourly',
};
