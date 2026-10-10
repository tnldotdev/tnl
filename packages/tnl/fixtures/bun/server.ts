/// <reference types="bun" />

import { Hono } from "hono";
import { tnl } from "@tnldotdev/tnl";

const publication = await tnl.prepare();
const app = new Hono();
const siblingURL = publication.services.web?.url;
app.get("/", (context) => context.json({ siblingURL }));

const server = Bun.serve({ fetch: app.fetch, hostname: "127.0.0.1", port: 0 });
await publication.register(server);
console.log(`listening=${server.port}`);
