import { control, createPublisherEnrollment } from "@tnldotdev/tnl/control";
import { INVITATION_PATH, READY_HEADER, credentialRequest, enrollmentKey } from "../enrollment.ts";
import { httpsOriginSchema } from "../peers/gossip.ts";
import { readJSON } from "../release.ts";

export type CredentialBindings = {
  CONTROL_URL: string;
  PROJECT_KEY?: string;
  TEAM_ID?: string;
  MANAGEMENT_TOKEN?: string;
  START_HOST: string;
};

export function enrollmentConfigured(
  env: CredentialBindings,
): env is CredentialBindings &
  Required<Pick<CredentialBindings, "MANAGEMENT_TOKEN" | "PROJECT_KEY" | "TEAM_ID">> {
  return Boolean(env.MANAGEMENT_TOKEN && env.PROJECT_KEY && env.TEAM_ID);
}

export async function credentials(
  request: Request,
  releaseID: string,
  env: CredentialBindings,
  peers: (signal: AbortSignal) => Response | Promise<Response>,
) {
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
  if (!enrollmentConfigured(env)) {
    return new Response(null, { status: 503, headers });
  }
  try {
    if (body.data.bootstrap && new URL(origin).hostname !== env.START_HOST)
      return new Response(null, { status: 403, headers });
    // the donor confirms its own invitation. only the separate restart origin
    // may seed an empty site without a donor.
    const check = body.data.bootstrap
      ? await peers(signal)
      : await fetch(new URL(INVITATION_PATH, body.data.inviter), {
          headers: { [READY_HEADER]: body.data.requestID, "X-Keepalive-Release": releaseID },
          redirect: "manual",
          cache: "no-store",
          signal,
        });
    await check.body?.cancel();
    if (body.data.bootstrap ? check.status !== 503 : check.status !== 204)
      return new Response(null, { status: 403, headers });
    const result = await createPublisherEnrollment({
      client: control({
        baseUrl: httpsOriginSchema.parse(env.CONTROL_URL),
        auth: env.MANAGEMENT_TOKEN,
      }),
      path: { project_key: env.PROJECT_KEY, deployment: "keepalive" },
      query: { team_id: env.TEAM_ID },
      headers: { "Idempotency-Key": body.data.requestID },
      body: { services: ["production"], max_members: 1, expires_in: 180 },
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
