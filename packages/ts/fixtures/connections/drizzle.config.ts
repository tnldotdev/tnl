import { tnl } from "@tnldotdev/tnl";
import { defineConfig } from "drizzle-kit";

const database = tnl.connect("database");
if (!("ssl" in database)) throw new Error("the database service must use postgres or mysql");

export default defineConfig({
  dialect: "postgresql",
  schema: "./schema.ts",
  out: "./migrations",
  dbCredentials: {
    ...database,
    user: process.env.DB_USER ?? "app",
    password: process.env.DB_PASSWORD ?? "application-owned",
    database: process.env.DB_NAME ?? "app",
  },
});
