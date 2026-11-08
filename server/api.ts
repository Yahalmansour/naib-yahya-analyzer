import crypto from 'node:crypto';
import { sql } from 'drizzle-orm';
import { analyzeContract, csvCell } from './analysis.ts';
import { all, isUniqueViolation, one, ts, TODAY, type Database, type SqlRunner } from './db-helpers.ts';
import {
  ApiError,
  contentDisposition,
  isMultipart,
  json,
  noContent,
  readJson,
  Router,
  withSecurityHeaders,
} from './http.ts';
import { hashPassword, makeToken, safeEqualString, verifyPassword, verifyToken } from './tokens.ts';

// Netlify Functions accept request bodies of up to 6 MB (including encoding overhead), so uploads are capped
// below that. Larger files would be rejected by the platform before reaching this code.
export const MAX_FILE_SIZE = 4 * 1024 * 1024;
export const MAX_PHOTO_SIZE = 4 * 1024 * 1024;
const MAX_FILE_LABEL = '4 ميجابايت';

const ALLOWED_TYPES: Record<string, string[]> = {
  '.pdf': ['application/pdf'],
  '.doc': ['application/msword', 'application/octet-stream'],
  '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/octet-stream'],
  '.xls': ['application/vnd.ms-excel', 'application/octet-stream'],
  '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/octet-stream'],
  '.jpg': ['image/jpeg'],
  '.jpeg': ['image/jpeg'],
  '.png': ['image/png'],
};
const PHOTO_ERRORS = {
  permitPhoto: 'صورة التصريح يجب أن تكون JPG أو PNG.',
  reportPhoto: 'صورة التقرير يجب أن تكون JPG أو PNG.',
  procedurePhoto: 'صورة الإجراء يجب أن تكون JPG أو PNG.',
  vehiclePhoto: 'صورة المركبة يجب أن تكون JPG أو PNG.',
} as const;
const FEATURE_CATEGORIES = ['إضافة ميزة', 'تحسين أداء', 'متطلب أمني', 'مشكلة', 'أخرى'];
const FEATURE_STATUSES = ['جديد', 'قيد المراجعة', 'مقبول', 'مرفوض', 'مكتمل'];
const AUTH_FAILURE_LIMIT = 10;
const AUTH_FAILURE_WINDOW_MINUTES = 15;

export interface MediaStore {
  set(key: string, data: ArrayBuffer): Promise<void>;
  get(key: string): Promise<Blob | null>;
  delete(key: string): Promise<void>;
}

export interface ApiDeps {
  db: Database;
  media: MediaStore;
  env: { get(name: string): string | undefined };
}

interface RequestContext {
  req: Request;
  url: URL;
  ip: string;
  userId: number;
  role: string;
}

interface UploadedFile {
  name: string;
  type: string;
  size: number;
  data: ArrayBuffer;
}

const extname = (name: string) => {
  const base = name.replaceAll('\\', '/').split('/').pop() || '';
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot).toLowerCase() : '';
};
const basename = (name: string) => (name.replaceAll('\\', '/').split('/').pop() || '').slice(0, 255);
const requiredText = (value: unknown, max: number): value is string =>
  typeof value === 'string' && value.trim().length > 0 && value.trim().length <= max;
const validDate = (value: unknown): value is string => {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
};
const validFullName = (value: unknown): value is string =>
  typeof value === 'string' &&
  /^[\p{L}\p{M}][\p{L}\p{M}\s.'-]{2,79}$/u.test(value.trim()) &&
  value.trim().split(/\s+/).length >= 2;
const validOwnerLoginId = (value: unknown): value is string =>
  typeof value === 'string' && /^[A-Za-z0-9_.-]{6,32}$/.test(value.trim());
const positiveId = (value: string) => {
  const id = Number(value);
  return Number.isSafeInteger(id) && id > 0 && id <= 2147483647 ? id : null;
};
const vehicleCode = () => `VH-${crypto.randomUUID().replaceAll('-', '').slice(0, 12).toUpperCase()}`;
const like = (search: string) => `%${search}%`;
const inList = (ids: number[]) => sql.join(ids.map((id) => sql`${id}`), sql`, `);

const PERMIT_STATUS = sql.raw(`CASE WHEN p.valid_from > (now() AT TIME ZONE 'UTC')::date THEN 'upcoming'
  WHEN p.valid_until < (now() AT TIME ZONE 'UTC')::date THEN 'expired'
  WHEN p.valid_until <= (now() AT TIME ZONE 'UTC')::date + 30 THEN 'expiring'
  ELSE 'active' END AS status`);
const PERMIT_COLUMNS = sql`p.id, p.permit_number, p.vehicle_plate, p.driver_name, p.identity_number, p.phone,
  p.organization, p.purpose, p.valid_from::text AS valid_from, p.valid_until::text AS valid_until, p.media_id,
  ${ts('p.created_at', 'created_at')}, v.vehicle_code`;
const ACCESS_COLUMNS = sql`a.id, a.person_name, a.identity_number, a.phone, a.organization, a.purpose, a.gate,
  a.person_count, a.vehicle_plate, a.vehicle_id, a.vehicle_photo_media_id, ${ts('a.entered_at', 'entered_at')},
  ${ts('a.exited_at', 'exited_at')}, a.created_by, v.vehicle_code`;
const ORGANIZATION_SELECT = sql`SELECT organization_name, work_location, ${ts('updated_at', 'updated_at')}
  FROM organization_profile WHERE id = 1`;

export function createApi(deps: ApiDeps) {
  const { db, media, env } = deps;
  let tokenSecretPromise: Promise<string> | undefined;

  // TOKEN_SECRET can be configured explicitly. Otherwise a random signing key is generated once and kept in the
  // database, so every function instance shares it and sessions survive cold starts and deploys.
  function tokenSecret(): Promise<string> {
    tokenSecretPromise ??= (async () => {
      const configured = env.get('TOKEN_SECRET');
      if (configured) {
        if (Buffer.byteLength(configured) < 32) throw new Error('TOKEN_SECRET must contain at least 32 bytes.');
        return configured;
      }
      await db.execute(sql`
        INSERT INTO app_secrets (name, value) VALUES ('token_secret', ${crypto.randomBytes(48).toString('hex')})
        ON CONFLICT (name) DO NOTHING
      `);
      const row = await one<{ value: string }>(db, sql`SELECT value FROM app_secrets WHERE name = 'token_secret'`);
      if (!row) throw new Error('Could not load the session signing key.');
      return row.value;
    })();
    tokenSecretPromise.catch(() => {
      tokenSecretPromise = undefined;
    });
    return tokenSecretPromise;
  }

  function setupKey() {
    const key = env.get('INITIAL_ADMIN_SETUP_KEY');
    if (!key) return undefined;
    if (Buffer.byteLength(key) < 32) {
      console.error('INITIAL_ADMIN_SETUP_KEY must contain at least 32 bytes; first-account setup is disabled.');
      return undefined;
    }
    return key;
  }

  async function audit(runner: SqlRunner, action: string, details: Record<string, unknown> = {}) {
    await runner.execute(sql`INSERT INTO audit_log (action, details) VALUES (${action}, ${JSON.stringify(details)})`);
  }

  async function getOrCreateVehicle(runner: SqlRunner, plateValue: string) {
    const plate = plateValue.trim().toUpperCase();
    if (!plate) return null;
    await runner.execute(sql`
      INSERT INTO vehicles (vehicle_code, vehicle_plate) VALUES (${vehicleCode()}, ${plate})
      ON CONFLICT (vehicle_plate) DO NOTHING
    `);
    return one<{ id: number; vehicle_code: string; vehicle_plate: string }>(
      runner,
      sql`SELECT id, vehicle_code, vehicle_plate FROM vehicles WHERE vehicle_plate = ${plate}`,
    );
  }

  async function attachMembers<T extends { id: number }>(records: T[]) {
    if (!records.length) return records.map((record) => ({ ...record, members: [] as unknown[] }));
    const members = await all<{ access_id: number; person_name: string; identity_number: string; phone: string }>(
      db,
      sql`SELECT access_id, person_name, identity_number, phone FROM security_access_members
        WHERE access_id IN (${inList(records.map((record) => record.id))}) ORDER BY id`,
    );
    const byAccess = new Map<number, unknown[]>();
    for (const member of members) {
      const list = byAccess.get(member.access_id) || [];
      list.push({ name: member.person_name, identity_number: member.identity_number, phone: member.phone });
      byAccess.set(member.access_id, list);
    }
    return records.map((record) => ({ ...record, members: byAccess.get(record.id) || [] }));
  }

  async function readForm(req: Request) {
    try {
      return await req.formData();
    } catch {
      throw new ApiError(400, 'تعذر رفع الملف.');
    }
  }

  function formFields(form: FormData) {
    const fields: Record<string, string> = {};
    form.forEach((value, key) => {
      if (typeof value === 'string' && !(key in fields)) fields[key] = value;
    });
    return fields;
  }

  async function takeFile(
    form: FormData,
    field: string,
    { maxSize, imagesOnly, typeError }: { maxSize: number; imagesOnly: boolean; typeError: string },
  ): Promise<UploadedFile | null> {
    const entries = form.getAll(field).filter((value): value is File => typeof value !== 'string');
    const files = entries.filter((file) => file.name || file.size > 0);
    if (!files.length) return null;
    if (files.length > 1) throw new ApiError(400, 'تعذر رفع الملف.');
    const [file] = files;
    const extension = extname(file.name);
    const type = file.type || 'application/octet-stream';
    if ((imagesOnly && !['.jpg', '.jpeg', '.png'].includes(extension)) || !ALLOWED_TYPES[extension]?.includes(type)) {
      throw new ApiError(400, typeError);
    }
    if (file.size > maxSize) throw new ApiError(400, `حجم الملف يتجاوز الحد الأقصى (${MAX_FILE_LABEL}).`);
    return { name: file.name, type, size: file.size, data: await file.arrayBuffer() };
  }

  /** Stores the file in Blobs first, then runs the database work; removes the blob again if that fails. */
  async function withStoredFile<T>(
    file: UploadedFile | null,
    extension: string | null,
    work: (filename: string | null) => Promise<T>,
  ): Promise<T> {
    const filename = file ? `${crypto.randomUUID()}${extension}` : null;
    if (file && filename) await media.set(filename, file.data);
    try {
      return await work(filename);
    } catch (error) {
      if (filename) await media.delete(filename).catch(() => {});
      throw error;
    }
  }

  async function insertMedia(runner: SqlRunner, filename: string, file: UploadedFile, category: string) {
    const row = await one<{ id: number }>(runner, sql`
      INSERT INTO media (filename, original_name, mime_type, size, category)
      VALUES (${filename}, ${basename(file.name)}, ${file.type}, ${file.size}, ${category})
      RETURNING id
    `);
    return row!.id;
  }

  const photoExtension = (file: UploadedFile) => (file.type === 'image/png' ? '.png' : '.jpg');
  const publicRouter = new Router<{ req: Request; ip: string }>();
  const router = new Router<RequestContext>();

  // ---------- Public endpoints ----------
  publicRouter.on('GET', '/api/health', async () => json({ status: 'ok' }));

  publicRouter.on('GET', '/api/auth/status', async () => {
    const row = await one<{ count: number }>(db, sql`SELECT COUNT(*)::int AS count FROM users`);
    return json({ configured: (row?.count || 0) > 0 });
  });

  publicRouter.on('POST', '/api/auth/register', async ({ req }) => {
    const { username, ownerLoginId, loginId, password, setupKey: providedKey } = await readJson(req);
    const ownerId = ownerLoginId || loginId;
    const expectedKey = setupKey();
    if (!expectedKey) {
      return json({ error: 'إعداد الحساب الأول غير متاح؛ اطلب من مسؤول الخادم تهيئة المنصة.' }, 503);
    }
    if (!safeEqualString(providedKey, expectedKey)) return json({ error: 'رمز إعداد المسؤول غير صحيح.' }, 403);
    if (!validFullName(username)) return json({ error: 'أدخل الاسم الكامل.' }, 400);
    if (!validOwnerLoginId(ownerId)) {
      return json({ error: 'معرف المالك يجب أن يتكون من 6 إلى 32 حرفاً إنجليزياً أو رقماً.' }, 400);
    }
    if (typeof password !== 'string' || password.length < 12 || password.length > 128) {
      return json({ error: 'كلمة المرور يجب أن تتكون من 12 حرفاً على الأقل.' }, 400);
    }
    const { salt, passwordHash } = await hashPassword(password);
    // The existence check and insert run in one statement so two concurrent setups cannot both create an admin.
    const created = await one<{ id: number }>(db, sql`
      INSERT INTO users (username, owner_login_id, password_hash, salt, role)
      SELECT ${username.trim()}, ${ownerId.trim()}, ${passwordHash}, ${salt}, 'admin'
      WHERE NOT EXISTS (SELECT 1 FROM users)
      RETURNING id
    `).catch((error) => {
      if (isUniqueViolation(error)) return undefined;
      throw error;
    });
    if (!created) {
      return json({ error: 'تم إعداد الحساب الأول مسبقاً. تواصل مع مسؤول النظام لإضافة مستخدم.' }, 403);
    }
    await audit(db, 'إنشاء الحساب الأول', { userId: created.id });
    return json({ token: makeToken(created.id, await tokenSecret()), username: username.trim() }, 201);
  });

  publicRouter.on('POST', '/api/auth/login', async ({ req }) => {
    const { loginId, identityNumber, username, password } = await readJson(req);
    const identifier =
      typeof loginId === 'string' ? loginId.trim() : typeof identityNumber === 'string' ? identityNumber.trim() : username;
    if (typeof identifier !== 'string' || typeof password !== 'string') {
      return json({ error: 'أدخل رقم الهوية وكلمة المرور.' }, 400);
    }
    const user = await one<{ id: number; username: string; salt: string; password_hash: string }>(db, sql`
      SELECT id, username, salt, password_hash FROM users
      WHERE owner_login_id = ${identifier} OR identity_number = ${identifier}
        OR (identity_number IS NULL AND owner_login_id IS NULL AND username = ${identifier})
      ORDER BY CASE WHEN owner_login_id = ${identifier} THEN 0 WHEN identity_number = ${identifier} THEN 1 ELSE 2 END
      LIMIT 1
    `);
    if (!(await verifyPassword(password, user))) {
      return json({ error: 'رقم الهوية أو كلمة المرور غير صحيحة.' }, 401);
    }
    return json({ token: makeToken(user!.id, await tokenSecret()), username: user!.username });
  });

  // ---------- Account & organization ----------
  const requireAdmin = (ctx: RequestContext) => {
    if (ctx.role !== 'admin') throw new ApiError(403, 'هذه العملية متاحة لمسؤول النظام فقط.');
  };

  router.on('GET', '/api/auth/me', async ({ userId }) => {
    const user = await one(db, sql`SELECT id, username, role, ${ts('created_at', 'created_at')} FROM users WHERE id = ${userId}`);
    if (!user) return json({ error: 'الحساب غير موجود.' }, 401);
    return json(user);
  });

  router.on('GET', '/api/organization', async () => json(await one(db, ORGANIZATION_SELECT)));

  router.on('PUT', '/api/organization', async (ctx) => {
    requireAdmin(ctx);
    const { organizationName, workLocation } = await readJson(ctx.req);
    if (
      typeof organizationName !== 'string' || !organizationName.trim() || organizationName.trim().length > 120 ||
      typeof workLocation !== 'string' || !workLocation.trim() || workLocation.trim().length > 200
    ) {
      return json({ error: 'أدخل اسم الجهة وموقع العمل (بحد أقصى 120 و200 حرف).' }, 400);
    }
    await db.execute(sql`
      INSERT INTO organization_profile (id, organization_name, work_location, updated_at, updated_by)
      VALUES (1, ${organizationName.trim()}, ${workLocation.trim()}, now(), ${ctx.userId})
      ON CONFLICT (id) DO UPDATE SET organization_name = EXCLUDED.organization_name,
        work_location = EXCLUDED.work_location, updated_at = now(), updated_by = EXCLUDED.updated_by
    `);
    await audit(db, 'تحديث اسم الجهة وموقع العمل', { userId: ctx.userId });
    return json(await one(db, ORGANIZATION_SELECT));
  });

  router.on('GET', '/api/users', async (ctx) => {
    requireAdmin(ctx);
    return json(await all(db, sql`
      SELECT id, username, identity_number, role, owner_login_id IS NOT NULL AS has_owner_login_id,
        ${ts('created_at', 'created_at')}
      FROM users ORDER BY id
    `));
  });

  const publicUser = (id: number) =>
    one(db, sql`SELECT id, username, identity_number, role, ${ts('created_at', 'created_at')} FROM users WHERE id = ${id}`);

  router.on('POST', '/api/users', async (ctx) => {
    requireAdmin(ctx);
    const { username, identityNumber, password, role = 'staff' } = await readJson(ctx.req);
    if (
      !validFullName(username) ||
      typeof identityNumber !== 'string' || !/^\d{10}$/.test(identityNumber.trim()) ||
      typeof password !== 'string' || password.length < 12 || password.length > 128 ||
      !['admin', 'staff'].includes(role)
    ) {
      return json({ error: 'تحقق من الاسم ورقم الهوية وكلمة المرور والصلاحية.' }, 400);
    }
    if (await one(db, sql`SELECT 1 FROM users WHERE owner_login_id = ${identityNumber.trim()}`)) {
      return json({ error: 'رقم الهوية مستخدم كمعرف دخول خاص.' }, 409);
    }
    const { salt, passwordHash } = await hashPassword(password);
    try {
      const created = await one<{ id: number }>(db, sql`
        INSERT INTO users (username, identity_number, password_hash, salt, role)
        VALUES (${username.trim()}, ${identityNumber.trim()}, ${passwordHash}, ${salt}, ${role})
        RETURNING id
      `);
      await audit(db, 'إنشاء مستخدم', { userId: created!.id, role });
      return json(await publicUser(created!.id), 201);
    } catch (error) {
      if (isUniqueViolation(error)) return json({ error: 'الاسم أو رقم الهوية مسجل مسبقاً.' }, 409);
      throw error;
    }
  });

  router.on('PATCH', '/api/users/:id/identity', async (ctx, params) => {
    requireAdmin(ctx);
    const id = positiveId(params.id);
    const { identityNumber } = await readJson(ctx.req);
    if (!id || typeof identityNumber !== 'string' || !/^\d{10}$/.test(identityNumber.trim())) {
      return json({ error: 'رقم الهوية يجب أن يتكون من 10 أرقام.' }, 400);
    }
    const user = await one<{ owner_login_id: string | null }>(db, sql`SELECT owner_login_id FROM users WHERE id = ${id}`);
    if (!user) return json({ error: 'المستخدم غير موجود.' }, 404);
    if (user.owner_login_id) return json({ error: 'حساب المالك يستخدم معرف دخول خاصاً، وليس رقم هوية.' }, 400);
    if (await one(db, sql`SELECT 1 FROM users WHERE id != ${id} AND owner_login_id = ${identityNumber.trim()}`)) {
      return json({ error: 'رقم الهوية مستخدم كمعرف دخول خاص.' }, 409);
    }
    try {
      await db.execute(sql`UPDATE users SET identity_number = ${identityNumber.trim()} WHERE id = ${id}`);
    } catch (error) {
      if (isUniqueViolation(error)) return json({ error: 'رقم الهوية مسجل مسبقاً.' }, 409);
      throw error;
    }
    await audit(db, 'تحديث رقم هوية مستخدم', { userId: id });
    return json(await publicUser(id));
  });

  router.on('PATCH', '/api/users/:id/owner-login', async (ctx, params) => {
    requireAdmin(ctx);
    const id = positiveId(params.id);
    const { ownerLoginId } = await readJson(ctx.req);
    if (!id || !validOwnerLoginId(ownerLoginId)) {
      return json({ error: 'معرف المالك يجب أن يتكون من 6 إلى 32 حرفاً إنجليزياً أو رقماً.' }, 400);
    }
    const user = await one<{ role: string }>(db, sql`SELECT role FROM users WHERE id = ${id}`);
    if (!user || user.role !== 'admin') return json({ error: 'حساب المسؤول غير موجود.' }, 404);
    if (id !== ctx.userId) return json({ error: 'يمكنك تغيير معرف دخول حسابك فقط.' }, 403);
    const value = ownerLoginId.trim();
    if (await one(db, sql`SELECT 1 FROM users WHERE id != ${id} AND (owner_login_id = ${value} OR identity_number = ${value}) LIMIT 1`)) {
      return json({ error: 'معرف الدخول مستخدم لحساب آخر.' }, 409);
    }
    try {
      await db.execute(sql`UPDATE users SET owner_login_id = ${value}, identity_number = NULL WHERE id = ${id}`);
    } catch (error) {
      if (isUniqueViolation(error)) return json({ error: 'معرف الدخول مستخدم لحساب آخر.' }, 409);
      throw error;
    }
    await audit(db, 'تحديث معرف دخول المالك', { userId: id });
    return json({ id, owner_login_configured: true });
  });

  // ---------- Feature requests ----------
  router.on('GET', '/api/feature-requests', async ({ role, userId }) =>
    json(await all(db, sql`
      SELECT r.id, r.category, r.message, r.status, ${ts('r.created_at', 'created_at')},
        ${ts('r.updated_at', 'updated_at')}, r.user_id, u.username AS requester_name
      FROM feature_requests r JOIN users u ON u.id = r.user_id
      WHERE (${role === 'admin'} OR r.user_id = ${userId})
      ORDER BY r.id DESC LIMIT 200
    `)),
  );

  router.on('POST', '/api/feature-requests', async (ctx) => {
    const { category, message } = await readJson(ctx.req);
    if (!FEATURE_CATEGORIES.includes(category) || typeof message !== 'string' || !message.trim() || message.trim().length > 2000) {
      return json({ error: 'اختر نوع الطلب واكتب رسالة من 1 إلى 2000 حرف.' }, 400);
    }
    const created = await one(db, sql`
      INSERT INTO feature_requests (category, message, user_id) VALUES (${category}, ${message.trim()}, ${ctx.userId})
      RETURNING id, category, message, status, ${ts('created_at', 'created_at')}, ${ts('updated_at', 'updated_at')}, user_id
    `);
    await audit(db, 'إرسال طلب تحسين', { requestId: created!.id, userId: ctx.userId });
    return json(created, 201);
  });

  router.on('PATCH', '/api/feature-requests/:id', async (ctx, params) => {
    requireAdmin(ctx);
    const id = positiveId(params.id);
    const { status } = await readJson(ctx.req);
    if (!id || !FEATURE_STATUSES.includes(status)) return json({ error: 'تحقق من رقم الطلب وحالته.' }, 400);
    const updated = await one(db, sql`
      UPDATE feature_requests SET status = ${status}, updated_at = now() WHERE id = ${id} RETURNING id
    `);
    if (!updated) return json({ error: 'الطلب غير موجود.' }, 404);
    await audit(db, 'تحديث حالة طلب تحسين', { requestId: id, status });
    return json({ id, status });
  });

  // ---------- Site security ----------
  router.on('GET', '/api/security/summary', async () => {
    const access = await one<{ people_inside: number; active_visits: number }>(db, sql`
      SELECT COALESCE(SUM(person_count), 0)::int AS people_inside, COUNT(*)::int AS active_visits
      FROM security_access WHERE exited_at IS NULL
    `);
    const permits = await one<{ expired: number; expiring: number }>(db, sql`
      SELECT
        COUNT(*) FILTER (WHERE valid_until < ${TODAY})::int AS expired,
        COUNT(*) FILTER (WHERE valid_from <= ${TODAY} AND valid_until >= ${TODAY}
          AND valid_until <= ${TODAY} + 30)::int AS expiring
      FROM vehicle_permits
    `);
    return json({
      people_inside: access!.people_inside,
      active_visits: access!.active_visits,
      expired_permits: permits!.expired || 0,
      expiring_permits: permits!.expiring || 0,
    });
  });

  router.on('GET', '/api/security/access', async ({ url }) => {
    const search = (url.searchParams.get('search') || '').trim().slice(0, 100);
    const status = url.searchParams.get('status') || 'all';
    if (!['all', 'inside', 'exited'].includes(status)) return json({ error: 'حالة سجل الدخول غير صالحة.' }, 400);
    const pattern = like(search);
    const records = await all<{ id: number }>(db, sql`
      SELECT a.id, a.person_name, a.identity_number, a.phone, a.organization, a.purpose, a.gate,
        a.person_count, a.vehicle_plate, ${ts('a.entered_at', 'entered_at')}, ${ts('a.exited_at', 'exited_at')},
        v.vehicle_code, a.vehicle_photo_media_id
      FROM security_access a LEFT JOIN vehicles v ON v.id = a.vehicle_id
      WHERE (${status} = 'all' OR (${status} = 'inside' AND a.exited_at IS NULL)
          OR (${status} = 'exited' AND a.exited_at IS NOT NULL))
        AND (${search} = '' OR a.person_name ILIKE ${pattern} OR a.identity_number ILIKE ${pattern}
          OR a.phone ILIKE ${pattern} OR a.organization ILIKE ${pattern} OR a.vehicle_plate ILIKE ${pattern}
          OR EXISTS (
            SELECT 1 FROM security_access_members m WHERE m.access_id = a.id
              AND (m.person_name ILIKE ${pattern} OR m.identity_number ILIKE ${pattern} OR m.phone ILIKE ${pattern})
          ))
      ORDER BY a.id DESC LIMIT 200
    `);
    return json(await attachMembers(records));
  });

  router.on('POST', '/api/security/access', async (ctx) => {
    let body: Record<string, any>;
    let photo: UploadedFile | null = null;
    if (isMultipart(ctx.req)) {
      const form = await readForm(ctx.req);
      photo = await takeFile(form, 'vehiclePhoto', {
        maxSize: MAX_PHOTO_SIZE,
        imagesOnly: true,
        typeError: PHOTO_ERRORS.vehiclePhoto,
      });
      body = formFields(form);
    } else {
      body = await readJson(ctx.req);
    }
    const { organization = '', purpose, gate, vehiclePlate = '' } = body;
    let people = body.people;
    if (typeof people === 'string') {
      try {
        people = JSON.parse(people);
      } catch {
        people = null;
      }
    }
    if (
      !Array.isArray(people) || people.length < 1 || people.length > 200 ||
      people.some((person) => !person || !requiredText(person.name, 120) ||
        !requiredText(person.identityNumber, 40) || !requiredText(person.phone, 30)) ||
      typeof organization !== 'string' || organization.trim().length > 120 ||
      !requiredText(purpose, 200) || !requiredText(gate, 80) ||
      typeof vehiclePlate !== 'string' || vehiclePlate.trim().length > 30
    ) {
      return json({ error: 'أدخل بيانات كل شخص (الاسم والهوية والهاتف) وتحقق من الجهة والغرض والبوابة.' }, 400);
    }
    const record = await withStoredFile(photo, photo && photoExtension(photo), (filename) =>
      db.transaction(async (tx) => {
        const [firstPerson] = people;
        const vehicle = await getOrCreateVehicle(tx, vehiclePlate);
        const photoMediaId = filename && photo ? await insertMedia(tx, filename, photo, 'صور المركبات عند البوابة') : null;
        const created = await one<{ id: number }>(tx, sql`
          INSERT INTO security_access
            (person_name, identity_number, phone, organization, purpose, gate, person_count,
              vehicle_plate, vehicle_id, vehicle_photo_media_id, created_by)
          VALUES (${firstPerson.name.trim()}, ${firstPerson.identityNumber.trim()}, ${firstPerson.phone.trim()},
            ${organization.trim()}, ${purpose.trim()}, ${gate.trim()}, ${people.length},
            ${vehicle?.vehicle_plate || ''}, ${vehicle?.id || null}, ${photoMediaId}, ${ctx.userId})
          RETURNING id
        `);
        for (const person of people) {
          await tx.execute(sql`
            INSERT INTO security_access_members (access_id, person_name, identity_number, phone)
            VALUES (${created!.id}, ${person.name.trim()}, ${person.identityNumber.trim()}, ${person.phone.trim()})
          `);
        }
        await audit(tx, 'تسجيل دخول للموقع', { accessId: created!.id, personCount: people.length });
        return one(tx, sql`
          SELECT ${ACCESS_COLUMNS} FROM security_access a LEFT JOIN vehicles v ON v.id = a.vehicle_id
          WHERE a.id = ${created!.id}
        `);
      }),
    );
    return json({
      ...record,
      members: people.map((person: any) => ({
        name: person.name.trim(),
        identity_number: person.identityNumber.trim(),
        phone: person.phone.trim(),
      })),
    }, 201);
  });

  router.on('POST', '/api/security/access/:id/exit', async (_ctx, params) => {
    const id = positiveId(params.id);
    if (!id) return json({ error: 'رقم السجل غير صالح.' }, 400);
    const record = await one<{ exited_at: string | null }>(db, sql`SELECT exited_at FROM security_access WHERE id = ${id}`);
    if (!record) return json({ error: 'سجل الدخول غير موجود.' }, 404);
    if (record.exited_at) return json({ error: 'تم تسجيل خروج هذا السجل مسبقاً.' }, 409);
    const updated = await one(db, sql`
      UPDATE security_access SET exited_at = now() WHERE id = ${id} AND exited_at IS NULL RETURNING id
    `);
    if (!updated) return json({ error: 'تم تسجيل خروج هذا السجل مسبقاً.' }, 409);
    await audit(db, 'تسجيل خروج من الموقع', { accessId: id });
    return json(await one(db, sql`
      SELECT ${ACCESS_COLUMNS} FROM security_access a LEFT JOIN vehicles v ON v.id = a.vehicle_id WHERE a.id = ${id}
    `));
  });

  router.on('GET', '/api/security/permits', async ({ url }) => {
    const search = (url.searchParams.get('search') || '').trim().slice(0, 100);
    const status = url.searchParams.get('status') || 'all';
    if (!['all', 'active', 'upcoming', 'expiring', 'expired'].includes(status)) {
      return json({ error: 'حالة التصريح غير صالحة.' }, 400);
    }
    const pattern = like(search);
    return json(await all(db, sql`
      SELECT ${PERMIT_COLUMNS}, ${PERMIT_STATUS}
      FROM vehicle_permits p LEFT JOIN vehicles v ON v.id = p.vehicle_id
      WHERE (${status} = 'all'
        OR (${status} = 'expired' AND p.valid_until < ${TODAY})
        OR (${status} = 'expiring' AND p.valid_from <= ${TODAY} AND p.valid_until >= ${TODAY} AND p.valid_until <= ${TODAY} + 30)
        OR (${status} = 'active' AND p.valid_from <= ${TODAY} AND p.valid_until > ${TODAY} + 30)
        OR (${status} = 'upcoming' AND p.valid_from > ${TODAY}))
        AND (${search} = '' OR p.permit_number ILIKE ${pattern} OR p.vehicle_plate ILIKE ${pattern}
          OR p.driver_name ILIKE ${pattern} OR p.identity_number ILIKE ${pattern} OR p.organization ILIKE ${pattern})
      ORDER BY p.valid_until ASC, p.id DESC LIMIT 100
    `));
  });

  router.on('GET', '/api/security/vehicles', async ({ url }) => {
    const plate = (url.searchParams.get('plate') || '').trim().toUpperCase();
    if (!plate || plate.length > 30) return json({ error: 'أدخل رقم لوحة صحيحاً للاستعلام.' }, 400);
    const vehicle = await one<{ vehicle_code: string }>(db, sql`
      SELECT vehicle_code FROM vehicles WHERE vehicle_plate = ${plate} OR vehicle_code = ${plate}
    `);
    const permits = await all<{ vehicle_plate: string; vehicle_code: string }>(db, sql`
      SELECT ${PERMIT_COLUMNS}, ${PERMIT_STATUS}
      FROM vehicle_permits p LEFT JOIN vehicles v ON v.id = p.vehicle_id
      WHERE UPPER(p.vehicle_plate) = ${plate} OR UPPER(v.vehicle_code) = ${plate}
      ORDER BY p.valid_until DESC, p.id DESC LIMIT 100
    `);
    const access = await attachMembers(await all<{ id: number; vehicle_plate: string; vehicle_code: string }>(db, sql`
      SELECT a.id, a.person_name, a.identity_number, a.phone, a.organization, a.purpose, a.gate,
        a.person_count, a.vehicle_plate, ${ts('a.entered_at', 'entered_at')}, ${ts('a.exited_at', 'exited_at')},
        v.vehicle_code, a.vehicle_photo_media_id
      FROM security_access a LEFT JOIN vehicles v ON v.id = a.vehicle_id
      WHERE UPPER(a.vehicle_plate) = ${plate} OR UPPER(v.vehicle_code) = ${plate}
      ORDER BY a.id DESC LIMIT 100
    `));
    return json({
      plate: permits[0]?.vehicle_plate || access[0]?.vehicle_plate || plate,
      vehicle_code: vehicle?.vehicle_code || permits[0]?.vehicle_code || access[0]?.vehicle_code || null,
      permits,
      access,
    });
  });

  router.on('POST', '/api/security/permits', async (ctx) => {
    const form = isMultipart(ctx.req) ? await readForm(ctx.req) : new FormData();
    const photo = await takeFile(form, 'permitPhoto', {
      maxSize: MAX_PHOTO_SIZE,
      imagesOnly: true,
      typeError: PHOTO_ERRORS.permitPhoto,
    });
    const {
      permitNumber, vehiclePlate, driverName, identityNumber, phone, organization = '', purpose, validFrom, validUntil,
    } = formFields(form);
    if (
      !photo || !requiredText(permitNumber, 80) || !requiredText(vehiclePlate, 30) ||
      !requiredText(driverName, 120) || !requiredText(identityNumber, 40) || !requiredText(phone, 30) ||
      organization.trim().length > 120 || !requiredText(purpose, 200) ||
      !validDate(validFrom) || !validDate(validUntil) || validUntil < validFrom
    ) {
      return json({ error: 'أكمل بيانات التصريح وتأكد من صحة فترة الصلاحية وإرفاق صورة JPG أو PNG.' }, 400);
    }
    try {
      const permit = await withStoredFile(photo, photoExtension(photo), (filename) =>
        db.transaction(async (tx) => {
          const vehicle = await getOrCreateVehicle(tx, vehiclePlate);
          const mediaId = await insertMedia(tx, filename!, photo, 'تصاريح المركبات');
          const created = await one<{ id: number }>(tx, sql`
            INSERT INTO vehicle_permits
              (permit_number, vehicle_plate, driver_name, identity_number, phone, organization,
                purpose, valid_from, valid_until, media_id, vehicle_id, created_by)
            VALUES (${permitNumber.trim()}, ${vehicle!.vehicle_plate}, ${driverName.trim()}, ${identityNumber.trim()},
              ${phone.trim()}, ${organization.trim()}, ${purpose.trim()}, ${validFrom}, ${validUntil},
              ${mediaId}, ${vehicle!.id}, ${ctx.userId})
            RETURNING id
          `);
          await audit(tx, 'إضافة تصريح مركبة', { permitId: created!.id });
          return one(tx, sql`
            SELECT ${PERMIT_COLUMNS} FROM vehicle_permits p JOIN vehicles v ON v.id = p.vehicle_id WHERE p.id = ${created!.id}
          `);
        }),
      );
      return json(permit, 201);
    } catch (error) {
      if (isUniqueViolation(error)) return json({ error: 'رقم التصريح مسجل مسبقاً.' }, 409);
      throw error;
    }
  });

  router.on('GET', '/api/security/reports', async () =>
    json(await all(db, sql`
      SELECT r.id, r.title, r.category, r.location, r.details, ${ts('r.created_at', 'created_at')},
        m.id AS media_id, m.original_name
      FROM security_reports r JOIN media m ON m.id = r.media_id
      ORDER BY r.id DESC LIMIT 100
    `)),
  );

  router.on('POST', '/api/security/reports', async (ctx) => {
    const form = isMultipart(ctx.req) ? await readForm(ctx.req) : new FormData();
    const photo = await takeFile(form, 'reportPhoto', {
      maxSize: MAX_PHOTO_SIZE,
      imagesOnly: true,
      typeError: PHOTO_ERRORS.reportPhoto,
    });
    const { title, category, location = '', details } = formFields(form);
    if (
      !photo || !requiredText(title, 150) || !['بلاغ ميداني', 'حادث', 'مخالفة', 'ملاحظة'].includes(category) ||
      location.trim().length > 100 || !requiredText(details, 2000)
    ) {
      return json({ error: 'أكمل عنوان التقرير ونوعه وتفاصيله وأرفق صورة JPG أو PNG.' }, 400);
    }
    const report = await withStoredFile(photo, photoExtension(photo), (filename) =>
      db.transaction(async (tx) => {
        const mediaId = await insertMedia(tx, filename!, photo, 'تقارير أمن الموقع');
        const created = await one<{ id: number }>(tx, sql`
          INSERT INTO security_reports (title, category, location, details, media_id, created_by)
          VALUES (${title.trim()}, ${category}, ${location.trim()}, ${details.trim()}, ${mediaId}, ${ctx.userId})
          RETURNING id
        `);
        await audit(tx, 'إضافة تقرير أمني', { reportId: created!.id });
        return one(tx, sql`
          SELECT r.id, r.title, r.category, r.location, r.details, ${ts('r.created_at', 'created_at')}, r.media_id
          FROM security_reports r WHERE r.id = ${created!.id}
        `);
      }),
    );
    return json(report, 201);
  });

  const PROCEDURE_SELECT = sql`SELECT p.id, p.title, p.category, p.location, p.details, ${ts('p.created_at', 'created_at')},
    p.created_by, u.username AS created_by_name, p.media_id
    FROM daily_procedures p JOIN users u ON u.id = p.created_by`;

  router.on('GET', '/api/security/procedures', async () =>
    json(await all(db, sql`${PROCEDURE_SELECT} ORDER BY p.id DESC LIMIT 200`)),
  );

  router.on('POST', '/api/security/procedures', async (ctx) => {
    const form = isMultipart(ctx.req) ? await readForm(ctx.req) : new FormData();
    const photo = await takeFile(form, 'procedurePhoto', {
      maxSize: MAX_PHOTO_SIZE,
      imagesOnly: true,
      typeError: PHOTO_ERRORS.procedurePhoto,
    });
    const { title, category, location = '', details } = formFields(form);
    if (
      !requiredText(title, 150) || !['جولة تفقدية', 'فحص تصريح', 'تسليم واستلام', 'إجراء أمني', 'أخرى'].includes(category) ||
      location.trim().length > 100 || !requiredText(details, 2000)
    ) {
      return json({ error: 'أكمل عنوان الإجراء ونوعه وتفاصيله.' }, 400);
    }
    const procedure = await withStoredFile(photo, photo && photoExtension(photo), (filename) =>
      db.transaction(async (tx) => {
        const mediaId = filename && photo ? await insertMedia(tx, filename, photo, 'الإجراءات اليومية') : null;
        const created = await one<{ id: number }>(tx, sql`
          INSERT INTO daily_procedures (title, category, location, details, media_id, created_by)
          VALUES (${title.trim()}, ${category}, ${location.trim()}, ${details.trim()}, ${mediaId}, ${ctx.userId})
          RETURNING id
        `);
        await audit(tx, 'تسجيل إجراء يومي', { procedureId: created!.id, userId: ctx.userId });
        return one(tx, sql`${PROCEDURE_SELECT} WHERE p.id = ${created!.id}`);
      }),
    );
    return json(procedure, 201);
  });

  // ---------- Documents ----------
  router.on('GET', '/api/documents', async () => {
    const documents = await all<{ analysis_json: string }>(db, sql`
      SELECT id, title, analysis_json, ${ts('created_at', 'created_at')} FROM documents ORDER BY id DESC
    `);
    return json(documents.map((document) => ({ ...document, analysis: JSON.parse(document.analysis_json) })));
  });

  router.on('POST', '/api/documents/analyze', async (ctx) => {
    const { title, content } = await readJson(ctx.req);
    if (
      typeof title !== 'string' || !title.trim() || title.length > 200 ||
      typeof content !== 'string' || !content.trim() || content.length > 1_000_000
    ) {
      return json({ error: 'أدخل عنواناً ونصاً للمستند (بحد أقصى مليون حرف).' }, 400);
    }
    const analysis = analyzeContract(content);
    const created = await one<{ id: number }>(db, sql`
      INSERT INTO documents (title, content, analysis_json) VALUES (${title.trim()}, ${content}, ${JSON.stringify(analysis)})
      RETURNING id
    `);
    await audit(db, 'تحليل مستند', { documentId: created!.id });
    return json({ id: created!.id, title: title.trim(), content, analysis }, 201);
  });

  router.on('GET', '/api/documents/:id', async (_ctx, params) => {
    const id = positiveId(params.id);
    const document = id
      ? await one<{ analysis_json: string }>(db, sql`
          SELECT id, title, content, analysis_json, ${ts('created_at', 'created_at')} FROM documents WHERE id = ${id}
        `)
      : undefined;
    if (!document) return json({ error: 'المستند غير موجود.' }, 404);
    return json({ ...document, analysis: JSON.parse(document.analysis_json) });
  });

  router.on('DELETE', '/api/documents/:id', async (_ctx, params) => {
    const id = positiveId(params.id);
    const deleted = id ? await one(db, sql`DELETE FROM documents WHERE id = ${id} RETURNING id`) : undefined;
    if (!deleted) return json({ error: 'المستند غير موجود.' }, 404);
    await audit(db, 'حذف مستند', { documentId: id });
    return noContent();
  });

  // ---------- Accounting ----------
  const TRANSACTION_COLUMNS = sql`id, kind, description, amount::float8 AS amount, currency,
    transaction_date::text AS transaction_date, ${ts('created_at', 'created_at')}`;

  router.on('GET', '/api/accounting/transactions', async ({ url }) => {
    const kind = url.searchParams.get('kind') || '';
    const search = url.searchParams.get('search') || '';
    if (kind && !['income', 'expense', 'purchase'].includes(kind)) return json({ error: 'نوع الحركة غير صالح.' }, 400);
    return json(await all(db, sql`
      SELECT ${TRANSACTION_COLUMNS} FROM transactions
      WHERE (${kind} = '' OR kind = ${kind}) AND (${search} = '' OR description ILIKE ${like(search)})
      ORDER BY transaction_date DESC, id DESC
    `));
  });

  router.on('POST', '/api/accounting/transactions', async (ctx) => {
    const { kind, description, amount, currency = 'SAR', date } = await readJson(ctx.req);
    if (
      !['income', 'expense', 'purchase'].includes(kind) ||
      typeof description !== 'string' || !description.trim() || description.length > 200 ||
      !Number.isFinite(amount) || amount <= 0 || amount > 1_000_000_000 ||
      typeof currency !== 'string' || !/^[A-Z]{3}$/.test(currency) || !validDate(date) ||
      Math.round(amount * 100) / 100 <= 0
    ) {
      return json({ error: 'تحقق من نوع الحركة والوصف والمبلغ والعملة والتاريخ.' }, 400);
    }
    const transaction = await one<{ id: number; amount: number }>(db, sql`
      INSERT INTO transactions (kind, description, amount, currency, transaction_date)
      VALUES (${kind}, ${description.trim()}, ${Math.round(amount * 100) / 100}, ${currency}, ${date})
      RETURNING ${TRANSACTION_COLUMNS}
    `);
    await audit(db, 'إضافة حركة مالية', { transactionId: transaction!.id, kind, amount: transaction!.amount });
    return json(transaction, 201);
  });

  router.on('DELETE', '/api/accounting/transactions/:id', async (_ctx, params) => {
    const id = positiveId(params.id);
    const deleted = id ? await one(db, sql`DELETE FROM transactions WHERE id = ${id} RETURNING id`) : undefined;
    if (!deleted) return json({ error: 'الحركة غير موجودة.' }, 404);
    await audit(db, 'حذف حركة مالية', { transactionId: id });
    return noContent();
  });

  router.on('GET', '/api/accounting/summary', async ({ url }) => {
    const year = url.searchParams.get('year') || String(new Date().getFullYear());
    if (!/^\d{4}$/.test(year)) return json({ error: 'السنة غير صالحة.' }, 400);
    const monthly = await all<{ month: string; income: number; expenses: number }>(db, sql`
      SELECT to_char(transaction_date, 'MM') AS month,
        SUM(CASE WHEN kind = 'income' THEN amount ELSE 0 END)::float8 AS income,
        SUM(CASE WHEN kind != 'income' THEN amount ELSE 0 END)::float8 AS expenses
      FROM transactions WHERE to_char(transaction_date, 'YYYY') = ${year} AND currency = 'SAR'
      GROUP BY month ORDER BY month
    `);
    const totals = monthly.reduce(
      (result, row) => ({ income: result.income + (row.income || 0), expenses: result.expenses + (row.expenses || 0) }),
      { income: 0, expenses: 0 },
    );
    return json({
      year: Number(year),
      currency: 'SAR',
      income: totals.income,
      expenses: totals.expenses,
      balance: totals.income - totals.expenses,
      monthly: Array.from({ length: 12 }, (_, i) => {
        const month = String(i + 1).padStart(2, '0');
        return monthly.find((row) => row.month === month) || { month, income: 0, expenses: 0 };
      }),
    });
  });

  router.on('GET', '/api/accounting/export.csv', async () => {
    const rows = await all<Record<string, unknown>>(db, sql`
      SELECT transaction_date::text AS transaction_date, kind, description, amount::float8 AS amount, currency
      FROM transactions ORDER BY transaction_date DESC
    `);
    const csv = [
      'التاريخ,النوع,الوصف,المبلغ,العملة',
      ...rows.map((row) =>
        [row.transaction_date, row.kind, row.description, row.amount, row.currency].map(csvCell).join(','),
      ),
    ].join('\r\n');
    return new Response(`﻿${csv}`, {
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="transactions.csv"',
      },
    });
  });

  // ---------- Media (files live in Netlify Blobs, metadata in the database) ----------
  const MEDIA_COLUMNS = sql`id, original_name, mime_type, size, category, ${ts('created_at', 'created_at')}`;

  router.on('GET', '/api/media', async () => json(await all(db, sql`SELECT ${MEDIA_COLUMNS} FROM media ORDER BY id DESC`)));

  router.on('POST', '/api/media', async (ctx) => {
    const form = isMultipart(ctx.req) ? await readForm(ctx.req) : new FormData();
    const file = await takeFile(form, 'file', {
      maxSize: MAX_FILE_SIZE,
      imagesOnly: false,
      typeError: 'نوع الملف غير مدعوم أو لا يطابق امتداده.',
    });
    if (!file) return json({ error: 'اختر ملفاً للرفع.' }, 400);
    const rawCategory = form.get('category');
    const category = typeof rawCategory === 'string' ? rawCategory.trim().slice(0, 80) || 'عام' : 'عام';
    const created = await withStoredFile(file, extname(file.name), async (filename) => {
      const row = await one<{ id: number }>(db, sql`
        INSERT INTO media (filename, original_name, mime_type, size, category)
        VALUES (${filename}, ${basename(file.name)}, ${file.type}, ${file.size}, ${category})
        RETURNING ${MEDIA_COLUMNS}
      `);
      await audit(db, 'رفع ملف', { mediaId: row!.id });
      return row;
    });
    return json(created, 201);
  });

  async function findMedia(idParam: string) {
    const id = positiveId(idParam);
    return id
      ? one<{ id: number; filename: string; original_name: string; mime_type: string }>(
          db,
          sql`SELECT id, filename, original_name, mime_type FROM media WHERE id = ${id}`,
        )
      : undefined;
  }

  async function mediaBody(filename: string) {
    const blob = await media.get(filename);
    if (!blob) throw new ApiError(404, 'الملف غير موجود.');
    return blob;
  }

  router.on('GET', '/api/media/:id/preview', async (_ctx, params) => {
    const file = await findMedia(params.id);
    if (!file) return json({ error: 'الملف غير موجود.' }, 404);
    if (!file.mime_type.startsWith('image/')) return json({ error: 'المعاينة متاحة للصور فقط.' }, 415);
    return new Response(await mediaBody(file.filename), { headers: { 'Content-Type': file.mime_type } });
  });

  router.on('GET', '/api/media/:id', async (_ctx, params) => {
    const file = await findMedia(params.id);
    if (!file) return json({ error: 'الملف غير موجود.' }, 404);
    return new Response(await mediaBody(file.filename), {
      headers: { 'Content-Type': file.mime_type, 'Content-Disposition': contentDisposition(file.original_name) },
    });
  });

  router.on('DELETE', '/api/media/:id', async (_ctx, params) => {
    const file = await findMedia(params.id);
    if (!file) return json({ error: 'الملف غير موجود.' }, 404);
    const linked = await one(db, sql`
      SELECT 1 FROM vehicle_permits WHERE media_id = ${file.id}
      UNION ALL SELECT 1 FROM security_reports WHERE media_id = ${file.id}
      UNION ALL SELECT 1 FROM daily_procedures WHERE media_id = ${file.id}
      UNION ALL SELECT 1 FROM security_access WHERE vehicle_photo_media_id = ${file.id}
      LIMIT 1
    `);
    if (linked) return json({ error: 'لا يمكن حذف صورة مرتبطة بتصريح أو تقرير أو سجل دخول أمني.' }, 409);
    await db.execute(sql`DELETE FROM media WHERE id = ${file.id}`);
    await media.delete(file.filename).catch((error) => console.error('Could not delete stored file:', error.message));
    await audit(db, 'حذف ملف', { mediaId: file.id });
    return noContent();
  });

  router.on('GET', '/api/audit', async () =>
    json(await all(db, sql`SELECT id, action, details, ${ts('created_at', 'created_at')} FROM audit_log ORDER BY id DESC LIMIT 100`)),
  );

  // ---------- Request pipeline ----------
  async function authFailureCount(clientKey: string) {
    const row = await one<{ count: number }>(db, sql`
      SELECT COUNT(*)::int AS count FROM auth_failures
      WHERE client_key = ${clientKey} AND created_at > now() - make_interval(mins => ${AUTH_FAILURE_WINDOW_MINUTES})
    `);
    return row?.count || 0;
  }

  async function recordAuthFailure(clientKey: string) {
    await db.execute(sql`INSERT INTO auth_failures (client_key) VALUES (${clientKey})`);
    await db.execute(sql`DELETE FROM auth_failures WHERE created_at < now() - interval '1 day'`);
  }

  async function authenticate(req: Request) {
    const result = verifyToken(req.headers.get('authorization'), await tokenSecret());
    if (!result.ok) throw new ApiError(401, result.error);
    const user = await one<{ id: number; role: string }>(db, sql`SELECT id, role FROM users WHERE id = ${result.userId}`);
    if (!user) throw new ApiError(401, 'الحساب غير موجود.');
    return user;
  }

  async function dispatch(req: Request, ip: string): Promise<Response> {
    const url = new URL(req.url);
    const method = req.method === 'HEAD' ? 'GET' : req.method;

    const publicMatch = publicRouter.match(method, url.pathname);
    if (publicMatch) {
      const isAuthAttempt = method === 'POST' && /^\/api\/auth\/(login|register)\/?$/.test(url.pathname);
      // Only failed attempts count, like the previous express-rate-limit setup (skipSuccessfulRequests).
      const clientKey = `auth:${ip || 'unknown'}`;
      if (isAuthAttempt && (await authFailureCount(clientKey)) >= AUTH_FAILURE_LIMIT) {
        return json({ error: 'محاولات كثيرة. حاول بعد 15 دقيقة.' }, 429);
      }
      const response = await publicMatch.handler({ req, ip }, publicMatch.params);
      if (isAuthAttempt && response.status >= 400) await recordAuthFailure(clientKey);
      return response;
    }

    const match = router.match(method, url.pathname);
    if (!match) return json({ error: 'المسار غير موجود.' }, 404);
    const user = await authenticate(req);
    return match.handler({ req, url, ip, userId: user.id, role: user.role }, match.params);
  }

  return async function handle(req: Request, ip = ''): Promise<Response> {
    let response: Response;
    try {
      response = await dispatch(req, ip);
    } catch (error) {
      if (error instanceof ApiError) {
        response = json({ error: error.message }, error.status);
      } else {
        console.error(error);
        response = json({ error: 'حدث خطأ داخلي.' }, 500);
      }
    }
    return withSecurityHeaders(response);
  };
}

