import { control, createPublisherEnrollment } from "@tnldotdev/tnl/control";
import { credentialRequest, enrollmentKey } from "./hosting/config.ts";
import { httpsOriginSchema } from "./peers.ts";
import { readJSON } from "./release.ts";

export type CredentialBindings = {
  CONTROL_URL: string;
  PROJECT_KEY?: string;
  TEAM_ID?: string;
  MANAGEMENT_TOKEN?: string;
  CERTIFICATE_PEM?: string;
  PRIVATE_KEY_PEM?: string;
};

export async function credentials(request: Request, releaseID: string, env: CredentialBindings) {
  const { origin } = new URL(request.url);
  const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };
  if (
    request.method !== "POST" ||
    request.headers.get("Origin") !== origin ||
    request.headers.get("Content-Type") !== "application/json"
  ) {
    return new Response(null, { status: 403, headers });
  }
  const signal = AbortSignal.any([request.signal, AbortSignal.timeout(10_000)]);
  const body = credentialRequest.safeParse(
    await readJSON(new Response(request.body), 1024, signal).catch(() => undefined),
  );
  if (!body.success || body.data.releaseID !== releaseID) {
    return new Response(null, { status: 400, headers });
  }
  if (!env.MANAGEMENT_TOKEN || !env.PROJECT_KEY || !env.TEAM_ID) {
    return new Response(null, { status: 503, headers });
  }
  try {
    const result = await createPublisherEnrollment({
      client: control({
        baseUrl: httpsOriginSchema.parse(env.CONTROL_URL),
        auth: env.MANAGEMENT_TOKEN,
      }),
      path: { project_key: env.PROJECT_KEY, deployment: "keepalive" },
      query: { team_id: env.TEAM_ID },
      headers: { "Idempotency-Key": body.data.requestID },
      body: { services: ["production"], max_members: 1, expires_in: 120 },
      cache: "no-store",
      redirect: "manual",
      signal,
    });
    if (result.response?.status !== 201) return new Response(null, { status: 503, headers });
    return Response.json(enrollmentKey.parse(result.data?.enrollment_key), { headers });
  } catch {
    return new Response(null, { status: 503, headers });
  }
}
