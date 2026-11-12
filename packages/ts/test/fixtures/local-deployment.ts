import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { Pool } from "pg";
import * as z from "zod";
import { createClient } from "../../dist/index.js";

const input = z
  .strictObject({
    directory: z.string(),
    user: z.string(),
    password: z.string(),
    database: z.string(),
  })
  .parse(JSON.parse(readFileSync(0, "utf8")));
const { services } = z
  .object({
    services: z.strictObject({ db: z.strictObject({ protocol: z.literal("postgres") }) }),
  })
  .parse(
    await import(pathToFileURL(path.join(input.directory, ".tnl/generated/services.ts")).href),
  );

process.chdir(input.directory);
const local = createClient({ services }).deployment("local");
const database = local.client("db", {
  create: (connection) =>
    new Pool({
      ...connection,
      user: input.user,
      password: input.password,
      database: input.database,
    }),
  close: (pool) => pool.end(),
});
try {
  const pool = await database();
  assert.equal(await database(), pool);
  const result = await pool.query<{ answer: number }>("select 42::int as answer");
  assert.equal(result.rows[0]?.answer, 42);
} finally {
  await local.close();
}
process.stdout.write("local PostgreSQL query passed\n");
