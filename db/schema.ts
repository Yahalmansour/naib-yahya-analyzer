import { sql } from "drizzle-orm";
import {
  check,
  date,
  index,
  integer,
  numeric,
  pgTable,
  serial,
  text,
  timestamp,
  unique,
} from "drizzle-orm/pg-core";

const createdAt = () => timestamp("created_at", { withTimezone: true }).notNull().defaultNow();

export const users = pgTable(
  "users",
  {
    id: serial().primaryKey(),
    username: text().notNull().unique(),
    identityNumber: text("identity_number").unique(),
    ownerLoginId: text("owner_login_id").unique(),
    passwordHash: text("password_hash").notNull(),
    salt: text().notNull(),
    role: text().notNull().default("staff"),
    createdAt: createdAt(),
  },
  (table) => [check("users_role_check", sql`${table.role} IN ('admin', 'staff')`)],
);

export const documents = pgTable("documents", {
  id: serial().primaryKey(),
  title: text().notNull(),
  content: text().notNull(),
  analysisJson: text("analysis_json").notNull(),
  createdAt: createdAt(),
});

export const transactions = pgTable(
  "transactions",
  {
    id: serial().primaryKey(),
    kind: text().notNull(),
    description: text().notNull(),
    amount: numeric({ precision: 14, scale: 2 }).notNull(),
    currency: text().notNull().default("SAR"),
    transactionDate: date("transaction_date").notNull(),
    createdAt: createdAt(),
  },
  (table) => [
    check("transactions_kind_check", sql`${table.kind} IN ('income', 'expense', 'purchase')`),
    check("transactions_amount_check", sql`${table.amount} > 0`),
    index("transactions_date_idx").on(table.transactionDate.desc(), table.id.desc()),
  ],
);

export const media = pgTable("media", {
  id: serial().primaryKey(),
  filename: text().notNull().unique(),
  originalName: text("original_name").notNull(),
  mimeType: text("mime_type").notNull(),
  size: integer().notNull(),
  category: text().notNull().default("عام"),
  createdAt: createdAt(),
});

export const auditLog = pgTable("audit_log", {
  id: serial().primaryKey(),
  action: text().notNull(),
  details: text().notNull(),
  createdAt: createdAt(),
});

export const vehicles = pgTable("vehicles", {
  id: serial().primaryKey(),
  vehicleCode: text("vehicle_code").notNull().unique(),
  vehiclePlate: text("vehicle_plate").notNull().unique(),
  createdAt: createdAt(),
});

export const securityAccess = pgTable(
  "security_access",
  {
    id: serial().primaryKey(),
    personName: text("person_name").notNull(),
    identityNumber: text("identity_number").notNull(),
    phone: text().notNull(),
    organization: text().notNull(),
    purpose: text().notNull(),
    gate: text().notNull(),
    personCount: integer("person_count").notNull(),
    vehiclePlate: text("vehicle_plate").notNull().default(""),
    vehicleId: integer("vehicle_id").references(() => vehicles.id),
    vehiclePhotoMediaId: integer("vehicle_photo_media_id").references(() => media.id),
    enteredAt: timestamp("entered_at", { withTimezone: true }).notNull().defaultNow(),
    exitedAt: timestamp("exited_at", { withTimezone: true }),
    createdBy: integer("created_by").references(() => users.id),
  },
  (table) => [
    check("security_access_person_count_check", sql`${table.personCount} > 0`),
    index("security_access_status_idx").on(table.exitedAt, table.id.desc()),
    index("security_access_vehicle_idx").on(table.vehicleId, table.id.desc()),
  ],
);

export const securityAccessMembers = pgTable(
  "security_access_members",
  {
    id: serial().primaryKey(),
    accessId: integer("access_id")
      .notNull()
      .references(() => securityAccess.id, { onDelete: "cascade" }),
    personName: text("person_name").notNull(),
    identityNumber: text("identity_number").notNull(),
    phone: text().notNull(),
  },
  (table) => [index("security_access_members_access_idx").on(table.accessId)],
);

export const vehiclePermits = pgTable(
  "vehicle_permits",
  {
    id: serial().primaryKey(),
    permitNumber: text("permit_number").notNull().unique(),
    vehiclePlate: text("vehicle_plate").notNull(),
    driverName: text("driver_name").notNull(),
    identityNumber: text("identity_number").notNull(),
    phone: text().notNull(),
    organization: text().notNull(),
    purpose: text().notNull(),
    validFrom: date("valid_from").notNull(),
    validUntil: date("valid_until").notNull(),
    mediaId: integer("media_id")
      .notNull()
      .references(() => media.id),
    vehicleId: integer("vehicle_id").references(() => vehicles.id),
    createdAt: createdAt(),
    createdBy: integer("created_by").references(() => users.id),
  },
  (table) => [
    index("vehicle_permits_expiry_idx").on(table.validUntil),
    index("vehicle_permits_vehicle_idx").on(table.vehicleId, table.id.desc()),
  ],
);

export const securityReports = pgTable("security_reports", {
  id: serial().primaryKey(),
  title: text().notNull(),
  category: text().notNull(),
  location: text().notNull().default(""),
  details: text().notNull(),
  mediaId: integer("media_id")
    .notNull()
    .references(() => media.id),
  createdAt: createdAt(),
  createdBy: integer("created_by").references(() => users.id),
});

export const dailyProcedures = pgTable("daily_procedures", {
  id: serial().primaryKey(),
  title: text().notNull(),
  category: text().notNull(),
  location: text().notNull().default(""),
  details: text().notNull(),
  mediaId: integer("media_id").references(() => media.id),
  createdAt: createdAt(),
  createdBy: integer("created_by")
    .notNull()
    .references(() => users.id),
});

export const featureRequests = pgTable(
  "feature_requests",
  {
    id: serial().primaryKey(),
    category: text().notNull(),
    message: text().notNull(),
    status: text().notNull().default("جديد"),
    createdAt: createdAt(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
    userId: integer("user_id")
      .notNull()
      .references(() => users.id),
  },
  (table) => [
    check(
      "feature_requests_category_check",
      sql`${table.category} IN ('إضافة ميزة', 'تحسين أداء', 'متطلب أمني', 'مشكلة', 'أخرى')`,
    ),
    check(
      "feature_requests_status_check",
      sql`${table.status} IN ('جديد', 'قيد المراجعة', 'مقبول', 'مرفوض', 'مكتمل')`,
    ),
  ],
);

export const organizationProfile = pgTable(
  "organization_profile",
  {
    id: integer().primaryKey(),
    organizationName: text("organization_name").notNull(),
    workLocation: text("work_location").notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
    updatedBy: integer("updated_by").references(() => users.id),
  },
  (table) => [check("organization_profile_singleton_check", sql`${table.id} = 1`)],
);

export const permitAlertDeliveries = pgTable(
  "permit_alert_deliveries",
  {
    id: serial().primaryKey(),
    permitId: integer("permit_id")
      .notNull()
      .references(() => vehiclePermits.id),
    alertType: text("alert_type").notNull(),
    attemptCount: integer("attempt_count").notNull().default(0),
    lastAttemptAt: timestamp("last_attempt_at", { withTimezone: true }),
    sentAt: timestamp("sent_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (table) => [
    check("permit_alert_deliveries_type_check", sql`${table.alertType} IN ('expiring', 'expired')`),
    unique("permit_alert_deliveries_permit_type_unique").on(table.permitId, table.alertType),
  ],
);

// Failed sign-in / setup attempts, used to throttle brute-force attempts per client IP
// across all function instances (the old in-memory limiter does not survive serverless scaling).
export const authFailures = pgTable(
  "auth_failures",
  {
    id: serial().primaryKey(),
    clientKey: text("client_key").notNull(),
    createdAt: createdAt(),
  },
  (table) => [index("auth_failures_client_idx").on(table.clientKey, table.createdAt)],
);

// Server-generated secrets (e.g. the session token signing key when TOKEN_SECRET is not configured).
export const appSecrets = pgTable("app_secrets", {
  name: text().primaryKey(),
  value: text().notNull(),
  createdAt: createdAt(),
});
