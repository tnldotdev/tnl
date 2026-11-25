import "../validation.ts";
import { Hono } from "hono";
import { credentials, type CredentialBindings } from "./credentials.ts";
import { deploymentCredential } from "./deployment-credential.ts";
import { CONFIG_PATH, CREDENTIALS_PATH, hostingConfig } from "../enrollment.ts";
import { HOST_PARENT, PEERS_PATH } from "../peers/gossip.ts";
import { AUDIENCE_PATH } from "../peers/presence.ts";
import { createProxy, siteHeaders } from "./proxy.ts";
import { ARTIFACT_PREFIX, RELEASE_PATH, contentType, releaseSchema } from "../release.ts";

declare const KEEPALIVE_RELEASE: unknown;
declare const KEEPALIVE_RAMP_PROXY_TRACE: boolean;
const release = releaseSchema.parse(KEEPALIVE_RELEASE);

type Bindings = CredentialBindings & {
  ASSETS: { fetch(request: Request): Promise<Response> };
  SITE_ORIGIN: string;
  START_HOST: string;
  SHARED_HOST?: string;
};

const app = new Hono<{ Bindings: Bindings }>();
const proxy = createProxy(
  release,
  fetch,
  typeof KEEPALIVE_RAMP_PROXY_TRACE !== "undefined" && KEEPALIVE_RAMP_PROXY_TRACE
    ? (trace) => console.info({ event: "keepalive_proxy_file", ...trace })
    : undefined,
);

app.use("*", async (c, next) => {
  const url = new URL(c.req.url);
  if (url.protocol === "http:") {
    const site = new URL(c.env.SITE_ORIGIN);
    if (
      site.protocol === "https:" &&
      (url.hostname === site.hostname || url.hostname === c.env.START_HOST)
    ) {
      url.protocol = "https:";
      url.port = "";
      return Response.redirect(url, 308);
    }
  }
  return next();
});

app.get(RELEASE_PATH, (c) => {
  if (c.req.method !== "GET" || new URL(c.req.url).search !== "") return c.body(null, 404);
  return c.json(release, 200, {
    ...siteHeaders("application/json"),
    "X-Keepalive-Host-Parent": HOST_PARENT,
  });
});
app.get(PEERS_PATH, (c) =>
  proxy.peers(c.req.raw, c.env.SHARED_HOST, (work) => c.executionCtx.waitUntil(work)),
);
app.get(AUDIENCE_PATH, (c) => proxy.audience(c.req.raw, (work) => c.executionCtx.waitUntil(work)));
app.post(CREDENTIALS_PATH, (c) =>
  credentials(c.req.raw, release.id, c.env, (signal) =>
    proxy.peers(new Request(new URL(PEERS_PATH, c.req.url), { signal }), c.env.SHARED_HOST),
  ),
);
app.post(CONFIG_PATH, (c) => {
  const origin = new URL(c.req.url).origin;
  if (c.req.header("Origin") !== origin) return c.body(null, 403);
  if (!deploymentCredential(c.env)) return c.body(null, 503, siteHeaders());
  const config = hostingConfig.parse({
    controlURL: c.env.CONTROL_URL,
    siteOrigin: c.env.SITE_ORIGIN,
    startHost: c.env.START_HOST,
  });
  return c.json(config, 200, siteHeaders("application/json"));
});
app.get("*", async (c) => {
  const request = c.req.raw;
  const url = new URL(request.url);
  if (url.hostname !== c.env.START_HOST) {
    return proxy.file(request, c.env.SHARED_HOST, (work) => c.executionCtx.waitUntil(work));
  }

  if (url.search !== "") return c.notFound();
  if (url.pathname.startsWith(ARTIFACT_PREFIX)) {
    const path = url.pathname.slice(ARTIFACT_PREFIX.length);
    if (!release.assets.some((asset) => asset.path === path)) return c.notFound();
    url.pathname = path;
  } else if (url.pathname === "/") {
    url.pathname = "/start.html";
  } else if (
    url.pathname.startsWith("/hosting/") ||
    !release.assets.some((asset) => asset.path === url.pathname)
  ) {
    return c.notFound();
  }
  const asset = await c.env.ASSETS.fetch(new Request(url, { signal: request.signal }));
  return new Response(asset.body, {
    status: asset.status,
    headers: siteHeaders(contentType(url.pathname)),
  });
});

export default app;
