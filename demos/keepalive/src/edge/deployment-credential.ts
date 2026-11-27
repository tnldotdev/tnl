import * as z from "zod/mini";
import { httpsOriginSchema } from "../peers/host.ts";
import { readJSON } from "../release.ts";

export const HOSTING_SERVICE = "production";

export type DeploymentBindings = {
  CONTROL_URL: string;
  TEAM_ID?: string;
  PROJECT_KEY?: string;
  DEPLOYMENT_ID?: string;
  DEPLOYMENT_CREDENTIAL?: string;
};

const opaqueID = (prefix: string) =>
  z.string().check(z.regex(new RegExp(`^${prefix}_[A-Za-z0-9]{22}$`)));

const credentialSchema = z.strictObject({
  version: z.literal(1),
  control_url: httpsOriginSchema,
  team: z.string(),
  approval: z.strictObject({
    team_id: opaqueID("tm"),
    project_key: z.string(),
    client_id: opaqueID("pub"),
    key_id: opaqueID("pkey"),
    grant_id: opaqueID("pgrant"),
    expires_at: z.pipe(z.iso.datetime({ offset: true }), z.transform(Date.parse)),
    all_deployments: z.literal(false),
    deployment_ids: z.tuple([opaqueID("dpl")]),
    permissions: z.strictObject({
      manage: z.strictObject({ [HOSTING_SERVICE]: z.literal("http") }),
    }),
  }),
  private_key: z.string().check(z.length(86)),
});

const tokenResponse = z.strictObject({
  access_token: z.string().check(z.regex(/^pta_[A-Za-z0-9_-]{43}$/)),
  token_type: z.literal("Bearer"),
  expires_in: z.int().check(z.minimum(1), z.maximum(300)),
  grant_id: opaqueID("pgrant"),
});

const utf8 = new TextEncoder();
const fromUTF8 = new TextDecoder("utf-8", { fatal: true });

function encode(bytes: Uint8Array) {
  return btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function decode(value: string) {
  const bytes = Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")), (char) =>
    char.charCodeAt(0),
  );
  if (encode(bytes) !== value) throw new Error("Invalid deployment credential.");
  return bytes;
}

// the CLI encodes a Go Ed25519 private key (32-byte seed followed by its public
// key). wrap only the seed in RFC 8410 PKCS#8 for Web Crypto.
const seedPrefix = decode("MC4CAQAwBQYDK2VwBCIEIA");

export function deploymentCredential(env: DeploymentBindings) {
  const value = env.DEPLOYMENT_CREDENTIAL;
  if (!value?.startsWith("tnc_") || value.length > 32 * 1024) return;
  try {
    const { control_url, approval, private_key } = credentialSchema.parse(
      JSON.parse(fromUTF8.decode(decode(value.slice(4)))),
    );
    const [deploymentID] = approval.deployment_ids;
    if (
      control_url !== env.CONTROL_URL ||
      approval.team_id !== env.TEAM_ID ||
      approval.project_key !== env.PROJECT_KEY ||
      deploymentID !== env.DEPLOYMENT_ID ||
      !(approval.expires_at > Date.now())
    )
      return;
    const key = decode(private_key);
    if (key.length !== 64) return;
    const pkcs8 = new Uint8Array(seedPrefix.length + 32);
    pkcs8.set(seedPrefix);
    pkcs8.set(key.subarray(0, 32), seedPrefix.length);

    return {
      controlURL: control_url,
      teamID: approval.team_id,
      projectKey: approval.project_key,
      deploymentID,
      // the envelope limits what this Worker will use, not what tnl authorizes.
      // let control verify the live grant on every enrollment.
      async accessToken(signal: AbortSignal) {
        signal.throwIfAborted();
        const audience = new URL("/v1/publisher-token", control_url);
        const issued = Math.floor(Date.now() / 1000);
        const key = await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", false, ["sign"]);
        const header = { alg: "EdDSA", typ: "JWT", kid: approval.key_id };
        const claims = {
          iss: approval.client_id,
          sub: approval.client_id,
          aud: audience.href,
          jti: encode(crypto.getRandomValues(new Uint8Array(24))),
          grant_id: approval.grant_id,
          iat: issued,
          exp: issued + 60,
        };
        const message = `${encode(utf8.encode(JSON.stringify(header)))}.${encode(utf8.encode(JSON.stringify(claims)))}`;
        const signature = await crypto.subtle.sign("Ed25519", key, utf8.encode(message));
        const response = await fetch(audience, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            grant_type: "client_credentials",
            client_id: approval.client_id,
            grant_id: approval.grant_id,
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion: `${message}.${encode(new Uint8Array(signature))}`,
          }),
          cache: "no-store",
          redirect: "manual",
          signal,
        });
        if (response.status === 200) {
          const token = tokenResponse.parse(await readJSON(response, 4096, signal));
          if (token.grant_id === approval.grant_id) return token.access_token;
        } else {
          await response.body?.cancel();
        }
        throw new Error("Deployment token exchange failed.");
      },
    };
  } catch {
    return;
  }
}
