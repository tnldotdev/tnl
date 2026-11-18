import { PrismaPg } from "@prisma/adapter-pg";
import { Kysely, PostgresDialect, sql } from "kysely";
import type { Pool } from "pg";

export async function checkPostgresORMs(
  pool: Pool,
  check: (value: unknown, message: string) => void,
) {
  const prisma = new PrismaPg(pool, { disposeExternalPool: false });
  const driver = await prisma.connect();
  try {
    check(driver.underlyingDriver() === pool, "Prisma did not use the supplied pool");
    const result = await driver.queryRaw({
      sql: "select $1::int + 1 as answer",
      args: [41],
      argTypes: [{ scalarType: "int", arity: "scalar" }],
    });
    check(result.rows[0]?.[0] === 42, "PrismaPg returned the wrong result");
  } finally {
    await driver.dispose();
  }

  // Kysely's destroy() ends its pool. Leave cleanup to the owning tnl client.
  const db = new Kysely({ dialect: new PostgresDialect({ pool }) });
  const result = await db
    .transaction()
    .execute((tx) => sql<{ answer: number }>`select ${41}::int + 1 as answer`.execute(tx));
  check(result.rows[0]?.answer === 42, "Kysely returned the wrong result");
}
