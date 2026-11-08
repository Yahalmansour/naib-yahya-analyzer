INSERT INTO "organization_profile" ("id", "organization_name", "work_location")
VALUES (1, 'المربع الجديد', 'شمال الرياض')
ON CONFLICT ("id") DO NOTHING;
