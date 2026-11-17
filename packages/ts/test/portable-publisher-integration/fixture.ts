import * as z from "zod";

// this descriptor is private test input, not browser-safe project metadata.
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
  named_url: z.url(),
  restricted_url: z.url(),
  relays: z
    .array(
      z.strictObject({
        address: z.string().min(1),
        dial_address: z.string().min(1),
        tls_server_name: z.string().min(1),
      }),
    )
    .length(2),
  spki_pins: z.array(z.string().regex(/^[A-Za-z0-9+/]{43}=$/)).min(3),
  api_url: z.url().refine((value) => new URL(value).hostname === "localhost"),
  api_token: z.string().min(1),
  runner_certificate_pem: z.string().min(1),
  runner_private_key_pem: z.string().min(1),
});
export type PublisherFixture = z.output<typeof fixtureSchema>;

export function check(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}

export const observationSchema = z.strictObject({
  service_id: z.string().min(1),
  run_number: z.number().int().nonnegative(),
  active_runs: z.number().int().nonnegative(),
  deleted: z.boolean(),
  orders: z.number().int().nonnegative(),
  status: z.number().int().nonnegative(),
  body: z.string(),
  certificate_sha256: z.string(),
  publisher_runtime: z.string(),
});
export type Observation = z.output<typeof observationSchema>;

export async function fixtureCall(
  fixture: PublisherFixture,
  route: "/observe" | "/exercise" | "/state" | "/await-restartable",
  url: string,
  fetcher: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> = globalThis.fetch,
): Promise<Observation> {
  const response = await fetcher(fixture.api_url + route, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Tnl-Fixture-Token": fixture.api_token },
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(route === "/await-restartable" ? 160_000 : 45_000),
  });
  check(response.ok, `publisher fixture ${route} returned HTTP ${response.status}`);
  return observationSchema.parse(await response.json());
}
