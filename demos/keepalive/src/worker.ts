import { Hono } from "hono";
import { credentials, type CredentialBindings } from "./credentials.ts";
import { CONFIG_PATH, CREDENTIALS_PATH, hostingConfig } from "./hosting/config.ts";
import { PEERS_PATH, SHARED_HOST } from "./peers.ts";
import { createProxy, siteHeaders } from "./proxy.ts";
import { ARTIFACT_PREFIX, RELEASE_PATH, contentType, releaseSchema } from "./release.ts";

declare const KEEPALIVE_RELEASE: unknown;
const release = releaseSchema.parse(KEEPALIVE_RELEASE);

type Bindings = CredentialBindings & {
  ASSETS: { fetch(request: Request): Promise<Response> };
  SITE_ORIGIN: string;
  START_HOST: string;
  SHARED_HOST?: string;
};

const app = new Hono<{ Bindings: Bindings }>();
app.post(CREDENTIALS_PATH, (c) => credentials(c.req.raw, release.id, c.env));
app.post(CONFIG_PATH, (c) => {
  const origin = new URL(c.req.url).origin;
  if (c.req.header("Origin") !== origin) return c.body(null, 403);
  const { CONTROL_URL, CERTIFICATE_PEM, PRIVATE_KEY_PEM } = c.env;
  const certificate =
    CERTIFICATE_PEM && PRIVATE_KEY_PEM
      ? { certificatePEM: CERTIFICATE_PEM, privateKeyPEM: PRIVATE_KEY_PEM }
      : undefined;
  const config = hostingConfig.parse({
    controlURL: CONTROL_URL,
    siteOrigin: c.env.SITE_ORIGIN,
    startHost: c.env.START_HOST,
    certificate,
  });
  return c.json(config, 200, siteHeaders("application/json"));
});
app.get("*", async (c) => {
  const request = c.req.raw;
  const url = new URL(request.url);
  if (url.hostname !== c.env.START_HOST || [RELEASE_PATH, PEERS_PATH].includes(url.pathname)) {
    return createProxy(release, fetch, c.env.SHARED_HOST ?? SHARED_HOST)(request);
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
