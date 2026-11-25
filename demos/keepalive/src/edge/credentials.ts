import { control, createPublisherEnrollment } from "@tnldotdev/tnl/control";
import { INVITATION_PATH, READY_HEADER, credentialRequest, enrollmentKey } from "../enrollment.ts";
import { readJSON } from "../release.ts";
import { noReachableHost, PEER_DISCOVERY_MS } from "../network.ts";
import {
  deploymentCredential,
  HOSTING_SERVICE,
  type DeploymentBindings,
} from "./deployment-credential.ts";

export type CredentialBindings = DeploymentBindings & {
  START_HOST: string;
};

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
  const signal = AbortSignal.any([request.signal, AbortSignal.timeout(PEER_DISCOVERY_MS + 8_000)]);
  const bodyDeadline = AbortSignal.any([signal, AbortSignal.timeout(3_000)]);
  const body = credentialRequest.safeParse(
    await readJSON(new Response(request.body), 1024, bodyDeadline).catch(() => undefined),
  );
  if (!body.success || body.data.releaseID !== releaseID) {
    return new Response(null, { status: 400, headers });
  }
  const deployment = deploymentCredential(env);
  if (!deployment) {
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
    if (body.data.bootstrap && check.status === 503 && !noReachableHost(check))
      return new Response(null, { status: 503, headers });
    if (body.data.bootstrap ? !noReachableHost(check) : check.status !== 204)
      return new Response(null, { status: 403, headers });
    const result = await createPublisherEnrollment({
      client: control({
        baseUrl: deployment.controlURL,
        auth: await deployment.accessToken(signal),
      }),
      path: { project_key: deployment.projectKey, deployment: deployment.deploymentID },
      query: { team_id: deployment.teamID },
      headers: { "Idempotency-Key": body.data.requestID },
      body: { services: [HOSTING_SERVICE], max_members: 1, expires_in: 180 },
      cache: "no-store",
      redirect: "manual",
      signal,
    });
    if (result.response?.status !== 201 || result.data?.deployment_id !== deployment.deploymentID)
      return new Response(null, { status: 503, headers });
    return Response.json(enrollmentKey.parse(result.data?.enrollment_key), { headers });
  } catch {
    return new Response(null, { status: 503, headers });
  }
}
