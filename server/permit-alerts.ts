import { sql } from 'drizzle-orm';
import type { SqlRunner } from './db-helpers.ts';
import { all } from './db-helpers.ts';

type Env = Record<string, string | undefined>;
type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string }) => Promise<{ ok: boolean; status?: number }>;

export interface PermitAlert {
  delivery_id?: number;
  alert_type: 'expiring' | 'expired';
  permit_number: string;
  vehicle_plate: string;
  valid_until: string;
}

export function createWhatsAppSender(config: Env, fetchImpl: FetchLike = fetch as unknown as FetchLike) {
  const {
    WHATSAPP_ACCESS_TOKEN: accessToken,
    WHATSAPP_PHONE_NUMBER_ID: phoneNumberId,
    WHATSAPP_ALERT_RECIPIENT: recipient,
    WHATSAPP_TEMPLATE_NAME: templateName,
    WHATSAPP_TEMPLATE_LANGUAGE: templateLanguage,
    WHATSAPP_API_VERSION: apiVersion,
  } = config;
  const values = [accessToken, phoneNumberId, recipient, templateName, templateLanguage, apiVersion];
  const configuredCount = values.filter((value) => typeof value === 'string' && value.length > 0).length;

  if (configuredCount === 0) return null;
  if (configuredCount !== values.length) {
    throw new Error('Configure all WhatsApp Cloud API environment variables or leave them all unset.');
  }
  if (
    !/^\d{5,30}$/.test(phoneNumberId!) ||
    !/^\d{8,15}$/.test(recipient!) ||
    !/^[a-zA-Z0-9_-]{1,128}$/.test(templateName!) ||
    !/^[a-z]{2,3}(?:_[A-Z]{2})?$/.test(templateLanguage!) ||
    !/^v\d+\.\d+$/.test(apiVersion!)
  ) {
    throw new Error('WhatsApp Cloud API configuration is invalid.');
  }

  return async function sendWhatsAppPermitAlert(permit: PermitAlert) {
    const statusText = permit.alert_type === 'expired' ? 'منتهي' : 'ينتهي خلال 30 يوماً';
    const response = await fetchImpl(`https://graph.facebook.com/${apiVersion}/${phoneNumberId}/messages`, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + accessToken,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        messaging_product: 'whatsapp',
        recipient_type: 'individual',
        to: recipient,
        type: 'template',
        template: {
          name: templateName,
          language: { code: templateLanguage },
          components: [
            {
              type: 'body',
              parameters: [
                { type: 'text', text: permit.permit_number },
                { type: 'text', text: permit.vehicle_plate },
                { type: 'text', text: permit.valid_until },
                { type: 'text', text: statusText },
              ],
            },
          ],
        },
      }),
    });
    if (!response.ok) throw new Error(`WhatsApp delivery failed with status ${response.status}.`);
  };
}

const RETRY_COOLDOWN_MINUTES = 55;

/**
 * Queues one "expiring" alert when a permit enters its final 30 days and one "expired" alert once it lapses,
 * then delivers up to 20 pending alerts. Each delivery is claimed atomically, so overlapping runs never
 * send the same alert twice; failed sends are retried after the cooldown.
 */
export function createPermitAlertRunner({
  db,
  sendAlert,
  now = () => new Date(),
}: {
  db: SqlRunner;
  sendAlert: ((alert: PermitAlert) => Promise<void>) | null;
  now?: () => Date;
}) {
  return async function sendDuePermitAlerts() {
    if (!sendAlert) return { disabled: true, sent: 0 };
    const current = now();
    const currentDate = current.toISOString().slice(0, 10);
    const plusThirty = new Date(`${currentDate}T00:00:00.000Z`);
    plusThirty.setUTCDate(plusThirty.getUTCDate() + 30);
    const expiringThrough = plusThirty.toISOString().slice(0, 10);
    const nowIso = current.toISOString();

    await db.execute(sql`
      INSERT INTO permit_alert_deliveries (permit_id, alert_type)
      SELECT id, 'expiring' FROM vehicle_permits
      WHERE valid_from <= ${currentDate}::date AND valid_until >= ${currentDate}::date
        AND valid_until <= ${expiringThrough}::date
      ON CONFLICT (permit_id, alert_type) DO NOTHING
    `);
    await db.execute(sql`
      INSERT INTO permit_alert_deliveries (permit_id, alert_type)
      SELECT id, 'expired' FROM vehicle_permits WHERE valid_until < ${currentDate}::date
      ON CONFLICT (permit_id, alert_type) DO NOTHING
    `);

    const claimed = await all<PermitAlert>(db, sql`
      WITH due AS (
        SELECT id FROM permit_alert_deliveries
        WHERE sent_at IS NULL
          AND (last_attempt_at IS NULL
            OR last_attempt_at <= ${nowIso}::timestamptz - make_interval(mins => ${RETRY_COOLDOWN_MINUTES}))
        ORDER BY id
        LIMIT 20
        FOR UPDATE SKIP LOCKED
      )
      UPDATE permit_alert_deliveries d
      SET attempt_count = d.attempt_count + 1, last_attempt_at = ${nowIso}::timestamptz
      FROM due, vehicle_permits p
      WHERE d.id = due.id AND p.id = d.permit_id
      RETURNING d.id AS delivery_id, d.alert_type, p.permit_number, p.vehicle_plate,
        p.valid_until::text AS valid_until
    `);
    claimed.sort((a, b) => Number(a.delivery_id) - Number(b.delivery_id));

    let sent = 0;
    for (const alert of claimed) {
      try {
        await sendAlert(alert);
        await db.execute(sql`
          UPDATE permit_alert_deliveries SET sent_at = ${now().toISOString()}::timestamptz
          WHERE id = ${alert.delivery_id} AND sent_at IS NULL
        `);
        sent += 1;
      } catch (error) {
        console.error(
          `WhatsApp permit alert delivery failed for delivery ${alert.delivery_id}:`,
          (error as Error).message,
        );
      }
    }
    return { disabled: false, sent, pending: claimed.length - sent };
  };
}
