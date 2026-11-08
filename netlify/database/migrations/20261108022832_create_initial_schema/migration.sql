CREATE TABLE "app_secrets" (
	"name" text PRIMARY KEY,
	"value" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit_log" (
	"id" serial PRIMARY KEY,
	"action" text NOT NULL,
	"details" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth_failures" (
	"id" serial PRIMARY KEY,
	"client_key" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "daily_procedures" (
	"id" serial PRIMARY KEY,
	"title" text NOT NULL,
	"category" text NOT NULL,
	"location" text DEFAULT '' NOT NULL,
	"details" text NOT NULL,
	"media_id" integer,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE "documents" (
	"id" serial PRIMARY KEY,
	"title" text NOT NULL,
	"content" text NOT NULL,
	"analysis_json" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "feature_requests" (
	"id" serial PRIMARY KEY,
	"category" text NOT NULL,
	"message" text NOT NULL,
	"status" text DEFAULT 'جديد' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"user_id" integer NOT NULL,
	CONSTRAINT "feature_requests_category_check" CHECK ("category" IN ('إضافة ميزة', 'تحسين أداء', 'متطلب أمني', 'مشكلة', 'أخرى')),
	CONSTRAINT "feature_requests_status_check" CHECK ("status" IN ('جديد', 'قيد المراجعة', 'مقبول', 'مرفوض', 'مكتمل'))
);
--> statement-breakpoint
CREATE TABLE "media" (
	"id" serial PRIMARY KEY,
	"filename" text NOT NULL UNIQUE,
	"original_name" text NOT NULL,
	"mime_type" text NOT NULL,
	"size" integer NOT NULL,
	"category" text DEFAULT 'عام' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "organization_profile" (
	"id" integer PRIMARY KEY,
	"organization_name" text NOT NULL,
	"work_location" text NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_by" integer,
	CONSTRAINT "organization_profile_singleton_check" CHECK ("id" = 1)
);
--> statement-breakpoint
CREATE TABLE "permit_alert_deliveries" (
	"id" serial PRIMARY KEY,
	"permit_id" integer NOT NULL,
	"alert_type" text NOT NULL,
	"attempt_count" integer DEFAULT 0 NOT NULL,
	"last_attempt_at" timestamp with time zone,
	"sent_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "permit_alert_deliveries_permit_type_unique" UNIQUE("permit_id","alert_type"),
	CONSTRAINT "permit_alert_deliveries_type_check" CHECK ("alert_type" IN ('expiring', 'expired'))
);
--> statement-breakpoint
CREATE TABLE "security_access" (
	"id" serial PRIMARY KEY,
	"person_name" text NOT NULL,
	"identity_number" text NOT NULL,
	"phone" text NOT NULL,
	"organization" text NOT NULL,
	"purpose" text NOT NULL,
	"gate" text NOT NULL,
	"person_count" integer NOT NULL,
	"vehicle_plate" text DEFAULT '' NOT NULL,
	"vehicle_id" integer,
	"vehicle_photo_media_id" integer,
	"entered_at" timestamp with time zone DEFAULT now() NOT NULL,
	"exited_at" timestamp with time zone,
	"created_by" integer,
	CONSTRAINT "security_access_person_count_check" CHECK ("person_count" > 0)
);
--> statement-breakpoint
CREATE TABLE "security_access_members" (
	"id" serial PRIMARY KEY,
	"access_id" integer NOT NULL,
	"person_name" text NOT NULL,
	"identity_number" text NOT NULL,
	"phone" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "security_reports" (
	"id" serial PRIMARY KEY,
	"title" text NOT NULL,
	"category" text NOT NULL,
	"location" text DEFAULT '' NOT NULL,
	"details" text NOT NULL,
	"media_id" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" integer
);
--> statement-breakpoint
CREATE TABLE "transactions" (
	"id" serial PRIMARY KEY,
	"kind" text NOT NULL,
	"description" text NOT NULL,
	"amount" numeric(14,2) NOT NULL,
	"currency" text DEFAULT 'SAR' NOT NULL,
	"transaction_date" date NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "transactions_kind_check" CHECK ("kind" IN ('income', 'expense', 'purchase')),
	CONSTRAINT "transactions_amount_check" CHECK ("amount" > 0)
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" serial PRIMARY KEY,
	"username" text NOT NULL UNIQUE,
	"identity_number" text UNIQUE,
	"owner_login_id" text UNIQUE,
	"password_hash" text NOT NULL,
	"salt" text NOT NULL,
	"role" text DEFAULT 'staff' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_role_check" CHECK ("role" IN ('admin', 'staff'))
);
--> statement-breakpoint
CREATE TABLE "vehicle_permits" (
	"id" serial PRIMARY KEY,
	"permit_number" text NOT NULL UNIQUE,
	"vehicle_plate" text NOT NULL,
	"driver_name" text NOT NULL,
	"identity_number" text NOT NULL,
	"phone" text NOT NULL,
	"organization" text NOT NULL,
	"purpose" text NOT NULL,
	"valid_from" date NOT NULL,
	"valid_until" date NOT NULL,
	"media_id" integer NOT NULL,
	"vehicle_id" integer,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" integer
);
--> statement-breakpoint
CREATE TABLE "vehicles" (
	"id" serial PRIMARY KEY,
	"vehicle_code" text NOT NULL UNIQUE,
	"vehicle_plate" text NOT NULL UNIQUE,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "auth_failures_client_idx" ON "auth_failures" ("client_key","created_at");--> statement-breakpoint
CREATE INDEX "security_access_status_idx" ON "security_access" ("exited_at","id" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "security_access_vehicle_idx" ON "security_access" ("vehicle_id","id" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "security_access_members_access_idx" ON "security_access_members" ("access_id");--> statement-breakpoint
CREATE INDEX "transactions_date_idx" ON "transactions" ("transaction_date" DESC NULLS LAST,"id" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "vehicle_permits_expiry_idx" ON "vehicle_permits" ("valid_until");--> statement-breakpoint
CREATE INDEX "vehicle_permits_vehicle_idx" ON "vehicle_permits" ("vehicle_id","id" DESC NULLS LAST);--> statement-breakpoint
ALTER TABLE "daily_procedures" ADD CONSTRAINT "daily_procedures_media_id_media_id_fkey" FOREIGN KEY ("media_id") REFERENCES "media"("id");--> statement-breakpoint
ALTER TABLE "daily_procedures" ADD CONSTRAINT "daily_procedures_created_by_users_id_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "feature_requests" ADD CONSTRAINT "feature_requests_user_id_users_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "organization_profile" ADD CONSTRAINT "organization_profile_updated_by_users_id_fkey" FOREIGN KEY ("updated_by") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "permit_alert_deliveries" ADD CONSTRAINT "permit_alert_deliveries_permit_id_vehicle_permits_id_fkey" FOREIGN KEY ("permit_id") REFERENCES "vehicle_permits"("id");--> statement-breakpoint
ALTER TABLE "security_access" ADD CONSTRAINT "security_access_vehicle_id_vehicles_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "vehicles"("id");--> statement-breakpoint
ALTER TABLE "security_access" ADD CONSTRAINT "security_access_vehicle_photo_media_id_media_id_fkey" FOREIGN KEY ("vehicle_photo_media_id") REFERENCES "media"("id");--> statement-breakpoint
ALTER TABLE "security_access" ADD CONSTRAINT "security_access_created_by_users_id_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "security_access_members" ADD CONSTRAINT "security_access_members_access_id_security_access_id_fkey" FOREIGN KEY ("access_id") REFERENCES "security_access"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "security_reports" ADD CONSTRAINT "security_reports_media_id_media_id_fkey" FOREIGN KEY ("media_id") REFERENCES "media"("id");--> statement-breakpoint
ALTER TABLE "security_reports" ADD CONSTRAINT "security_reports_created_by_users_id_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "vehicle_permits" ADD CONSTRAINT "vehicle_permits_media_id_media_id_fkey" FOREIGN KEY ("media_id") REFERENCES "media"("id");--> statement-breakpoint
ALTER TABLE "vehicle_permits" ADD CONSTRAINT "vehicle_permits_vehicle_id_vehicles_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "vehicles"("id");--> statement-breakpoint
ALTER TABLE "vehicle_permits" ADD CONSTRAINT "vehicle_permits_created_by_users_id_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id");