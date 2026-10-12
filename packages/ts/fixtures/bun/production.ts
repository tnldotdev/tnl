/// <reference types="bun" />

import { Hono } from "hono";

const app = new Hono();
const databaseHost =
  process.env.DATABASE_URL === undefined ? null : new URL(process.env.DATABASE_URL).hostname;
app.get("/", (context) => context.json({ databaseHost }));
const server = Bun.serve({ fetch: app.fetch, hostname: "127.0.0.1", port: 0 });

if (process.env.NODE_ENV !== "production") {
  const { tnl } = await import("@tnldotdev/tnl");
  const handle = await tnl.prepare({ service: "api" });
  await handle.register(server);
}

console.log(`listening=${server.port}`);
