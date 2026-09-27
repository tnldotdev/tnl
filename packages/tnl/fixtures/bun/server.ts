/// <reference types="bun" />

import { Hono } from "hono";
import { tnl } from "@tnldotdev/tnl";

const app = new Hono();
const siblingURL = tnl.services?.web?.url;
app.get("/", (context) => context.json({ siblingURL }));

const server = Bun.serve({ fetch: app.fetch, hostname: "127.0.0.1", port: tnl.port });
await tnl.register(server);
console.log(`listening=${server.port}`);
