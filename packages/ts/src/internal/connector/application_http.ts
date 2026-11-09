import * as z from "zod";
import type { TnlApplicationCredential, TnlApplicationResource } from "../../credential.js";
import { TnlError, privateTnlError } from "../../errors.js";
import { parseValue } from "../validation.js";
import { hostnameSchema, httpsOriginSchema } from "../values.js";
import { credentialSchema } from "./http_credential.js";
import { cancellable } from "./cancellation.js";
import { decodeBase64, encodeBase64, parseApplicationCredential } from "../credential.js";

const id = (prefix: string) => z.string().regex(new RegExp(`^${prefix}[A-Za-z0-9]{22}$`));
const resourceSchema = z.union([id("url_"), id("svc_")]);
const accessSchema = z.strictObject({
  access_token: z.string().regex(/^pta_[A-Za-z0-9_-]{43}$/),
  token_type: z.literal("Bearer"),
  expires_in: z.number().int().min(1).max(300),
  grant_id: id("pgrant_"),
});
const permissionSchema = z.strictObject({
  resource: z.strictObject({ kind: z.enum(["public_url", "service"]), id: resourceSchema }),
  hostname: hostnameSchema,
  port: z.number().int().min(1).max(65535),
  visitor_token: credentialSchema,
  visitor_policy_revision: z.number().int().positive(),
  service_trust_revision: z.number().int().positive().optional(),
  service_protocol: z.enum(["http", "tcp", "mysql", "postgres", "kubernetes"]).optional(),
  service_endpoint: z
    .strictObject({
      hostname: hostnameSchema,
      port: z.number().int().min(1024).max(65535),
      public: z.boolean(),
    })
    .optional(),
  expires_at: z.iso.datetime({ offset: true }),
});

type Selection = Readonly<{
  key: string;
  url: `https://${string}`;
  credential: string;
  expires: number;
}>;

// this owner exchanges only the selected application's exact visit grant. its
// renewable authority is separate from ordinary client binding and app requests.
export function applicationHTTP(value: TnlApplicationCredential, lifetime: AbortSignal) {
  const file = parseApplicationCredential(value);
  const current = new Map<string, Selection>();
  const pending = new Map<string, Promise<Selection>>();
  let signing: Promise<{ private: CryptoKey; public: CryptoKey }> | undefined;
  const active = () => lifetime.throwIfAborted();
  const keys = () =>
    (signing ??= (async () => {
      const raw = decodeBase64(file.private_key);
      const encoded = new Uint8Array(48);
      encoded.set([
        0x30, 0x2e, 0x02, 0x01, 0, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
      ]);
      encoded.set(raw.subarray(0, 32), 16);
      try {
        const [privateKey, publicKey] = await Promise.all([
          globalThis.crypto.subtle.importKey("pkcs8", encoded, "Ed25519", false, ["sign"]),
          globalThis.crypto.subtle.importKey("raw", raw.subarray(32), "Ed25519", false, ["verify"]),
        ]);
        return { private: privateKey, public: publicKey };
      } catch (cause) {
        throw privateTnlError("sdk.credential_invalid", cause);
      } finally {
        raw.fill(0);
        encoded.fill(0);
      }
    })());
  const json = async (path: string, body: unknown): Promise<unknown> => {
    active();
    const signal = AbortSignal.any([lifetime, AbortSignal.timeout(15_000)]);
    let response: Response;
    try {
      response = await globalThis.fetch(`${file.control_url}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal,
        redirect: "manual",
        credentials: "omit",
      });
    } catch (cause) {
      if (lifetime.aborted) throw lifetime.reason;
      throw privateTnlError("sdk.credential_unavailable", cause);
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      throw new TnlError(
        response.status === 401 ||
          response.status === 403 ||
          response.status === 404 ||
          response.status === 409 ||
          response.status === 410
          ? "sdk.credential_denied"
          : response.status >= 500 || response.status === 429
            ? "sdk.credential_unavailable"
            : "sdk.credential_response_invalid",
      );
    }
    const reader = response.body?.getReader();
    if (reader === undefined) throw new TnlError("sdk.credential_response_invalid");
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    try {
      for (;;) {
        const part = await cancellable(signal, () => reader.read());
        if (part.done) break;
        bytes += part.value.byteLength;
        if (bytes > 65536) throw new TnlError("sdk.credential_response_invalid");
        chunks.push(part.value);
      }
      const body = new Uint8Array(bytes);
      let offset = 0;
      for (const chunk of chunks) {
        body.set(chunk, offset);
        offset += chunk.byteLength;
      }
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)) as unknown;
    } catch (cause) {
      await reader.cancel().catch(() => {});
      if (lifetime.aborted) throw lifetime.reason;
      if (signal.aborted) throw privateTnlError("sdk.credential_unavailable", cause);
      if (cause instanceof TnlError) throw cause;
      throw privateTnlError("sdk.credential_response_invalid", cause);
    } finally {
      reader.releaseLock();
    }
  };
  const acquire = async (resource: TnlApplicationResource): Promise<Selection> => {
    active();
    if (globalThis.crypto?.subtle === undefined) throw new TnlError("sdk.protocol_unsupported");
    parseValue(resourceSchema, resource, "sdk.credential_denied");
    const grant = file.grants.find(
      (grant) =>
        grant.operation === "visit" &&
        (grant.kind === "service"
          ? grant.service_id === resource
          : grant.kind === "saved_public_url" && grant.public_url_id === resource),
    );
    if (
      grant === undefined ||
      (grant.expires_at !== undefined && Date.parse(grant.expires_at) <= Date.now())
    )
      throw new TnlError("sdk.credential_denied");
    const started = Date.now();
    const now = Math.floor(started / 1000);
    const header = encodeBase64(
      new TextEncoder().encode(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: file.key_id })),
    );
    const claims = encodeBase64(
      new TextEncoder().encode(
        JSON.stringify({
          iss: file.client_id,
          sub: file.client_id,
          aud: `${file.control_url}/v1/publisher-token`,
          jti: encodeBase64(globalThis.crypto.getRandomValues(new Uint8Array(24))),
          grant_id: grant.id,
          iat: now,
          exp: now + 60,
        }),
      ),
    );
    const message = new TextEncoder().encode(`${header}.${claims}`);
    const selected = await keys();
    active();
    let signature: ArrayBuffer;
    try {
      signature = await globalThis.crypto.subtle.sign("Ed25519", selected.private, message);
      if (!(await globalThis.crypto.subtle.verify("Ed25519", selected.public, signature, message)))
        throw new Error("key binding");
    } catch (cause) {
      throw privateTnlError("sdk.credential_invalid", cause);
    }
    active();
    const access = parseValue(
      accessSchema,
      await json("/v1/publisher-token", {
        grant_type: "client_credentials",
        client_id: file.client_id,
        grant_id: grant.id,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: `${header}.${claims}.${encodeBase64(new Uint8Array(signature))}`,
      }),
      "sdk.credential_response_invalid",
    );
    if (access.grant_id !== grant.id) throw new TnlError("sdk.credential_response_invalid");
    const kind = grant.kind === "service" ? "service" : "public_url";
    const permission = parseValue(
      permissionSchema,
      await json("/v1/visitor-tokens", {
        resource: { kind, id: resource },
        source: { kind: "application", credential: access.access_token },
      }),
      "sdk.credential_response_invalid",
    );
    active();
    if (
      permission.resource.kind !== kind ||
      permission.resource.id !== resource ||
      (kind === "public_url" &&
        (permission.port !== 443 ||
          permission.service_protocol !== undefined ||
          permission.service_endpoint !== undefined ||
          permission.service_trust_revision !== undefined))
    )
      throw new TnlError("sdk.credential_response_invalid");
    if (kind === "service") {
      const endpoint = permission.service_endpoint;
      if (
        endpoint === undefined ||
        endpoint.hostname !== permission.hostname ||
        endpoint.port !== permission.port ||
        permission.service_trust_revision === undefined ||
        permission.service_protocol === undefined
      )
        throw new TnlError("sdk.credential_response_invalid");
      if (permission.service_protocol !== "http") throw new TnlError("sdk.protocol_unsupported");
      if (!endpoint.public) throw new TnlError("sdk.credential_denied");
    }
    const url = parseValue(
      httpsOriginSchema,
      `https://${permission.hostname}${permission.port === 443 ? "" : `:${permission.port}`}`,
      "sdk.credential_response_invalid",
    );
    const expires = Math.min(
      Date.parse(permission.expires_at),
      started + access.expires_in * 1000,
      grant.expires_at === undefined ? Infinity : Date.parse(grant.expires_at),
    );
    if (expires <= Date.now()) throw new TnlError("sdk.credential_denied");
    return {
      key: JSON.stringify([
        file.control_url,
        file.client_id,
        file.key_id,
        grant.id,
        url,
        permission.service_trust_revision ?? 0,
      ]),
      url,
      credential: permission.visitor_token,
      expires,
    };
  };
  return {
    controlURL: file.control_url,
    resolve(resource: TnlApplicationResource): Promise<Selection> {
      active();
      const cached = current.get(resource);
      if (cached !== undefined && cached.expires - Date.now() > 30_000)
        return Promise.resolve(cached);
      const existing = pending.get(resource);
      if (existing !== undefined) return existing;
      const work = acquire(resource)
        .then((selected) => {
          active();
          current.set(resource, selected);
          return selected;
        })
        .catch((cause: unknown) => {
          if (lifetime.aborted) throw lifetime.reason;
          if (cause instanceof TnlError) throw cause;
          throw privateTnlError("sdk.credential_invalid", cause);
        });
      pending.set(resource, work);
      void work.then(
        () => pending.delete(resource),
        () => pending.delete(resource),
      );
      return work;
    },
    async finished() {
      await Promise.allSettled(pending.values());
    },
  };
}
