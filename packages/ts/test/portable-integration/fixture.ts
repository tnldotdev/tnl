import * as z from "zod";

const credentials = z.strictObject({
  user: z.string().min(1),
  password: z.string().min(1),
  database: z.string().min(1),
});
const names = ["http", "tcp", "postgres", "mysql", "kubernetes", "redis"] as const;
const endpoint = z
  .object({
    hostname: z.string().min(1),
    port: z.number().int().min(0).max(65535),
    public: z.literal(false),
  })
  .passthrough();
const named = <Value extends z.ZodType>(value: Value) => z.record(z.enum(names), value);

// this is a private test descriptor, not the SDK's configuration format.
export const fixtureSchema = z.strictObject({
  version: z.literal(1),
  project: z.string().regex(/^[^/]+\/[^/]+$/),
  deployment: z.string().min(1),
  token: z.string().min(1),
  control_url: z.url(),
  control_dial_address: z.string().min(1),
  control_root_pem: z.string().min(1),
  relay_root_pem: z.string().min(1),
  service_root_pem: z.string().min(1),
  services: named(z.string().min(1)),
  endpoints: named(endpoint),
  relays: z
    .array(
      z.strictObject({
        address: z.string().min(1),
        dial_address: z.string().min(1),
        tls_server_name: z.string().min(1),
      }),
    )
    .length(2),
  spki_pins: z.array(z.string().regex(/^[A-Za-z0-9+/]{43}=$/)).length(3),
  api_url: z.url().refine((value) => new URL(value).hostname === "127.0.0.1"),
  api_token: z.string().min(1),
  postgres: credentials,
  mysql: credentials,
  redis_password: z.string().min(1),
  kubernetes_token: z.string().min(1),
  source_fingerprint: z.string().regex(/^[0-9a-f]{64}$/),
});

export type PortableFixture = z.output<typeof fixtureSchema>;
export type Credentials = z.output<typeof credentials>;

export class FixtureAssertionError extends Error {}

export async function fixtureCall(
  fixture: PortableFixture,
  path: string,
  body: unknown,
  signal?: AbortSignal,
): Promise<unknown> {
  const timeout = AbortSignal.timeout(30_000);
  const response = await fetch(fixture.api_url + path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Tnl-Fixture-Token": fixture.api_token,
    },
    body: JSON.stringify(body),
    signal: signal === undefined ? timeout : AbortSignal.any([timeout, signal]),
  });
  if (!response.ok) throw new Error(`fixture operation ${path} failed: HTTP ${response.status}`);
  if (response.status === 204) return undefined;
  return response.json();
}

export async function committedRows(fixture: PortableFixture, id: string): Promise<number> {
  const result = z
    .strictObject({ committed_rows: z.number().int().min(0).max(1) })
    .parse(await fixtureCall(fixture, "/observe/postgres", { id }));
  return result.committed_rows;
}

export function check(value: unknown, message: string): asserts value {
  if (!value) throw new FixtureAssertionError(message);
}
