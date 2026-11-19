import "./validation.ts";
import { Hono } from "hono";
import { credentials, enrollmentConfigured, type CredentialBindings } from "./credentials.ts";
import { CONFIG_PATH, CREDENTIALS_PATH, hostingConfig } from "./hosting/config.ts";
import {
  NETWORK_CHECK_PATH,
  NETWORK_PROOF_PATH,
  compareNetworks,
  proveNetwork,
} from "./network.ts";
import { PEERS_PATH } from "./peers.ts";
import { createProxy, siteHeaders } from "./proxy.ts";
import { ARTIFACT_PREFIX, RELEASE_PATH, contentType, releaseSchema } from "./release.ts";

declare const KEEPALIVE_RELEASE: unknown;
const release = releaseSchema.parse(KEEPALIVE_RELEASE);

type Bindings = CredentialBindings & {
  ASSETS: { fetch(request: Request): Promise<Response> };
  SITE_ORIGIN: string;
  START_HOST: string;
  SHARED_HOST?: string;
  NETWORK_SECRET?: string;
};

async function requestNetworkProof(request: Request, secret?: string) {
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || !secret || secret.length < 32) return undefined;
  return proveNetwork(ip, secret).catch(() => undefined);
}

const app = new Hono<{ Bindings: Bindings }>();
const proxy = createProxy(release);

app.get(RELEASE_PATH, (c) => {
  if (c.req.method !== "GET" || new URL(c.req.url).search !== "") return c.body(null, 404);
  return c.json(release, 200, siteHeaders("application/json"));
});
app.get(PEERS_PATH, (c) => proxy.peers(c.req.raw, c.env.SHARED_HOST));
app.post(CREDENTIALS_PATH, (c) => credentials(c.req.raw, release.id, c.env));
app.post(NETWORK_PROOF_PATH, async (c) => {
  if (c.req.header("Origin") !== new URL(c.req.url).origin) return c.body(null, 403);
  const proof = await requestNetworkProof(c.req.raw, c.env.NETWORK_SECRET);
  if (proof === undefined) return c.body(null, 503);
  return c.json(proof, 200, siteHeaders("application/json"));
});
app.post(CONFIG_PATH, async (c) => {
  const origin = new URL(c.req.url).origin;
  if (c.req.header("Origin") !== origin) return c.body(null, 403);
  if (!enrollmentConfigured(c.env)) return c.body(null, 503, siteHeaders());
  const { CONTROL_URL, CERTIFICATE_PEM, PRIVATE_KEY_PEM, NETWORK_SECRET } = c.env;
  const proof = await requestNetworkProof(c.req.raw, NETWORK_SECRET);
  if (proof === undefined) return c.body(null, 503, siteHeaders());
  const certificate =
    CERTIFICATE_PEM && PRIVATE_KEY_PEM
      ? { certificatePEM: CERTIFICATE_PEM, privateKeyPEM: PRIVATE_KEY_PEM }
      : undefined;
  const config = hostingConfig.parse({
    controlURL: CONTROL_URL,
    siteOrigin: c.env.SITE_ORIGIN,
    startHost: c.env.START_HOST,
    certificate,
    networkProof: proof,
  });
  return c.json(config, 200, siteHeaders("application/json"));
});
app.post(NETWORK_CHECK_PATH, async (c) => {
  if (!c.env.NETWORK_SECRET || c.env.NETWORK_SECRET.length < 32) return c.body(null, 503);
  const different = await compareNetworks(c.req.raw, c.env.NETWORK_SECRET).catch(() => false);
  return c.body(null, different ? 204 : 403, siteHeaders());
});
app.get("*", async (c) => {
  const request = c.req.raw;
  const url = new URL(request.url);
  if (url.hostname !== c.env.START_HOST) {
    return proxy.file(request, c.env.SHARED_HOST);
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
