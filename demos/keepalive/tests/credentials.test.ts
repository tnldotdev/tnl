import { generateKeyPairSync, verify } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { credentials, type CredentialBindings } from "../src/edge/credentials.ts";
import { READY_HEADER } from "../src/enrollment.ts";
import { HOST_PARENT } from "../src/peers/gossip.ts";

const id = (prefix: string, suffix = "a") => `${prefix}_${suffix.repeat(22)}`;
const release = "a".repeat(64);
const env = {
  CONTROL_URL: "https://control.test",
  START_HOST: "start.test",
  PROJECT_KEY: "project",
  TEAM_ID: id("tm"),
  DEPLOYMENT_ID: id("dpl"),
};
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const { x, d } = privateKey.export({ format: "jwk" });
if (!x || !d) throw new Error("No fixture key.");
const approval = {
  client_id: id("pub"),
  key_id: id("pkey"),
  grant_id: id("pgrant"),
  team_id: env.TEAM_ID,
  project_key: env.PROJECT_KEY,
  permissions: { manage: { production: "http" } },
  deployment_ids: [env.DEPLOYMENT_ID],
  all_deployments: false,
  expires_at: new Date(Date.now() + 600_000).toISOString(),
};
const credential = {
  version: 1,
  control_url: env.CONTROL_URL,
  team: "keepalive",
  approval,
  private_key: Buffer.concat([Buffer.from(d, "base64url"), Buffer.from(x, "base64url")]).toString(
    "base64url",
  ),
};
const encode = (value: unknown) =>
  `tnc_${Buffer.from(JSON.stringify(value)).toString("base64url")}`;
const configured = { ...env, DEPLOYMENT_CREDENTIAL: encode(credential) };
const requestID = crypto.randomUUID();
const donor = `https://p-${"a".repeat(26)}.${HOST_PARENT}`;
const call = (
  origin: string,
  bootstrap: boolean,
  peers: (signal: AbortSignal) => Response | Promise<Response> = vi.fn(),
  inviter = donor,
  bindings: CredentialBindings = configured,
) =>
  credentials(
    new Request(origin, {
      method: "POST",
      headers: { Origin: origin, "Content-Type": "application/json" },
      body: JSON.stringify({
        releaseID: release,
        requestID,
        bootstrap,
        ...(bootstrap ? {} : { inviter }),
      }),
    }),
    release,
    bindings,
    peers,
  );
afterEach(() => vi.unstubAllGlobals());

const token = {
  access_token: `pta_${"A".repeat(43)}`,
  token_type: "Bearer",
  expires_in: 300,
  grant_id: approval.grant_id,
};
const exchangeURL = `${env.CONTROL_URL}/v1/publisher-token`;
const enrollmentURL =
  `${env.CONTROL_URL}/v1/projects/${env.PROJECT_KEY}/deployments/${env.DEPLOYMENT_ID}` +
  `/publisher-enrollments?team_id=${env.TEAM_ID}`;
const enrolled = () =>
  Response.json(
    {
      enrollment_id: id("pen"),
      enrollment_key: "one-use-enrollment-fixture",
      deployment_id: env.DEPLOYMENT_ID,
      expires_at: new Date(Date.now() + 180_000).toISOString(),
      max_members: 1,
      services: { production: "http" },
    },
    { status: 201 },
  );

it("checks a live invitation, signs for control, and returns only the one-use enrollment", async () => {
  const assertions = new Set<string>();
  const seen: string[] = [];
  let ready = false;
  const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
    const req = new Request(input, init);
    seen.push(req.url);
    if (req.url.startsWith(donor)) {
      expect(req.headers.get(READY_HEADER)).toBe(requestID);
      return new Response(null, { status: ready ? 204 : 403 });
    }
    expect(req.method).toBe("POST");
    expect(req.redirect).toBe("manual");
    const body: unknown = await req.json();
    if (req.url === exchangeURL) {
      expect(req.headers.has("Authorization")).toBe(false);
      expect(body).toEqual({
        grant_type: "client_credentials",
        client_id: approval.client_id,
        grant_id: approval.grant_id,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: expect.any(String),
      });
      if (
        !body ||
        typeof body !== "object" ||
        !("client_assertion" in body) ||
        typeof body.client_assertion !== "string"
      )
        throw new Error("No signed assertion.");
      const [header, claims, signature] = body.client_assertion.split(".");
      if (!header || !claims || !signature) throw new Error("No signed assertion.");
      const issued = Math.floor(Date.now() / 1000);
      expect(JSON.parse(Buffer.from(header, "base64url").toString("utf8"))).toEqual({
        alg: "EdDSA",
        typ: "JWT",
        kid: approval.key_id,
      });
      const payload = JSON.parse(Buffer.from(claims, "base64url").toString("utf8"));
      expect(payload).toEqual({
        iss: approval.client_id,
        sub: approval.client_id,
        aud: exchangeURL,
        jti: expect.stringMatching(/^[A-Za-z0-9_-]{32}$/),
        grant_id: approval.grant_id,
        iat: expect.any(Number),
        exp: payload.iat + 60,
      });
      expect(Math.abs(issued - payload.iat)).toBeLessThan(5);
      expect(assertions.has(payload.jti)).toBe(false);
      assertions.add(payload.jti);
      expect(
        verify(
          null,
          Buffer.from(`${header}.${claims}`),
          publicKey,
          Buffer.from(signature, "base64url"),
        ),
      ).toBe(true);
      return Response.json(token);
    }
    expect(req.url).toBe(enrollmentURL);
    expect(req.headers.get("Authorization")).toBe(`Bearer ${token.access_token}`);
    expect(req.headers.get("Idempotency-Key")).toBe(requestID);
    expect(body).toEqual({ services: ["production"], max_members: 1, expires_in: 180 });
    return enrolled();
  });
  vi.stubGlobal("fetch", fetch);
  expect((await call("https://site.test", false, undefined, "https://other.test")).status).toBe(
    400,
  );
  expect(fetch).not.toHaveBeenCalled();
  expect((await call("https://site.test", false)).status).toBe(403);
  expect(seen).toEqual([`${donor}/__keepalive/invitation`]);
  ready = true;
  for (let i = 0; i < 2; i++) {
    const response = await call("https://site.test", false);
    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(await response.json()).toBe("one-use-enrollment-fixture");
  }
  expect(assertions.size).toBe(2);
});

it("only the restart site can seed, and only when no publisher answers", async () => {
  const fetch = vi
    .fn<typeof globalThis.fetch>()
    .mockResolvedValueOnce(Response.json(token))
    .mockResolvedValueOnce(enrolled());
  vi.stubGlobal("fetch", fetch);
  const peers = vi
    .fn<() => Promise<Response>>()
    .mockResolvedValueOnce(new Response("alive"))
    .mockResolvedValueOnce(new Response(null, { status: 503 }));
  expect((await call("https://site.test", true, peers)).status).toBe(403);
  expect((await call("https://start.test", true, peers)).status).toBe(403);
  expect(fetch).not.toHaveBeenCalled();
  expect((await call("https://start.test", true, peers)).status).toBe(200);
  expect(fetch).toHaveBeenCalledTimes(2);
});

it.each([
  ["missing", ""],
  ["malformed", "tnc_abc"],
  ["wrong control", encode({ ...credential, control_url: "https://other.test" })],
  ["wrong team", encode({ ...credential, approval: { ...approval, team_id: id("tm", "b") } })],
  ["wrong project", encode({ ...credential, approval: { ...approval, project_key: "elsewhere" } })],
  [
    "wrong deployment",
    encode({ ...credential, approval: { ...approval, deployment_ids: [id("dpl", "b")] } }),
  ],
  ["all deployments", encode({ ...credential, approval: { ...approval, all_deployments: true } })],
  [
    "extra service",
    encode({
      ...credential,
      approval: { ...approval, permissions: { manage: { production: "http", extra: "http" } } },
    }),
  ],
  [
    "connection grant",
    encode({
      ...credential,
      approval: {
        ...approval,
        permissions: { ...approval.permissions, connect: { production: "http" } },
      },
    }),
  ],
  [
    "expired",
    encode({ ...credential, approval: { ...approval, expires_at: "2020-01-01T00:00:00Z" } }),
  ],
])("rejects a %s credential before any network call", async (_name, value) => {
  const fetch = vi.fn<typeof globalThis.fetch>();
  const peers = vi.fn<() => Response>();
  vi.stubGlobal("fetch", fetch);
  const response = await call("https://start.test", true, peers, donor, {
    ...env,
    DEPLOYMENT_CREDENTIAL: value,
  });
  expect(response.status).toBe(503);
  expect(await response.text()).toBe("");
  expect(fetch).not.toHaveBeenCalled();
  expect(peers).not.toHaveBeenCalled();
});

it.each([
  ["denied", () => new Response("private upstream error", { status: 403 })],
  ["redirect", () => Response.redirect("https://other.test")],
  ["different grant", () => Response.json({ ...token, grant_id: id("pgrant", "b") })],
  ["invalid token lifetime", () => Response.json({ ...token, expires_in: 301 })],
])("does not enroll a publisher if the token exchange is %s", async (_name, reply) => {
  const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValueOnce(reply());
  vi.stubGlobal("fetch", fetch);
  const response = await call(
    "https://start.test",
    true,
    () => new Response(null, { status: 503 }),
  );
  expect(response.status).toBe(503);
  expect(await response.text()).toBe("");
  expect(fetch).toHaveBeenCalledTimes(1);
});
