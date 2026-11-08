import { drizzle } from "drizzle-orm/netlify-db";
import * as schema from "./schema.ts";

type Database = ReturnType<typeof drizzle<typeof schema>>;
let instance: Database | undefined;

// Created lazily so modules can be imported (e.g. in unit tests) without a database connection.
export function getDb(): Database {
  instance ??= drizzle({ schema });
  return instance;
}
