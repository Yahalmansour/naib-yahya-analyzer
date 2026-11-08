import { sql, type SQL } from 'drizzle-orm';

// Anything that can run raw SQL: the Drizzle database or a transaction handle.
export interface SqlRunner {
  execute(query: SQL): PromiseLike<unknown>;
}
export interface Database extends SqlRunner {
  transaction<T>(fn: (tx: SqlRunner) => Promise<T>): Promise<T>;
}

export async function all<T = Record<string, any>>(runner: SqlRunner, query: SQL): Promise<T[]> {
  const result = (await runner.execute(query)) as { rows?: T[] } | T[];
  return Array.isArray(result) ? result : result.rows ?? [];
}

export async function one<T = Record<string, any>>(runner: SqlRunner, query: SQL): Promise<T | undefined> {
  return (await all<T>(runner, query))[0];
}

export function isUniqueViolation(error: unknown): boolean {
  let current: any = error;
  for (let depth = 0; current && depth < 5; depth += 1) {
    if (current.code === '23505') return true;
    current = current.cause;
  }
  return false;
}

/** Formats a timestamptz column as the UTC "YYYY-MM-DD HH:MM:SS" string the frontend expects. */
export function ts(expression: string, alias: string): SQL {
  if (!/^[a-z_.]+$/.test(expression) || !/^[a-z_]+$/.test(alias)) throw new Error('Invalid column reference.');
  return sql.raw(`to_char(${expression} AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') AS ${alias}`);
}

/** Current date in UTC (the original SQLite date('now') semantics). */
export const TODAY = sql.raw(`(now() AT TIME ZONE 'UTC')::date`);
