import { randomUUID } from "node:crypto";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import * as z from "zod";
import { privateTnlError, TnlError } from "../../errors.js";
import type { TnlConnectionHandle, TnlConnectionRegistry } from "../../project.js";
import { digestSchema, httpsOriginSchema, protocolSchema, serviceNameSchema } from "../values.js";
import { parseValue } from "../validation.js";
import { boundedAssertion } from "./workload/provider.js";
import { cancellable } from "./cancellation.js";
import { closeConnectionScope, connectionHandle, type ConnectionScope } from "./connection.js";

const policySchema = z.strictObject({
  provider: z.enum(["github", "vercel", "fly", "oidc", "google", "kubernetes", "gitlab"]),
  services: z
    .array(serviceNameSchema)
    .min(1)
    .max(32)
    .refine((services) => new Set(services).size === services.length),
  max_duration_seconds: z.int().min(0).max(9223372036),
});

const connectionSchema = z
  .strictObject({
    schema: z.literal(1),
    server: httpsOriginSchema,
    team_id: z.string().regex(/^tm_[A-Za-z0-9]{22}$/),
    project_key: z.string().regex(/^[a-z][a-z0-9-]{0,62}$/),
    source_fingerprint: digestSchema,
    project_label: z.string().regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/),
    group_id: z.string().regex(/^pgrp_[A-Za-z0-9]{22}$/),
    group_name: serviceNameSchema,
    services: z
      .record(serviceNameSchema, protocolSchema)
      .refine((value) => Object.keys(value).length > 0 && Object.keys(value).length <= 128),
    workloads: z
      .record(serviceNameSchema, policySchema)
      .refine((value) => Object.keys(value).length <= 32),
  })
  .readonly();

export type TnlGroupConnection = z.output<typeof connectionSchema>;
export type TnlGroupClientOptions = Readonly<{
  connection: TnlGroupConnection;
  workload: Readonly<{ name: string; token: () => Promise<string> }>;
}>;

type Settings = TnlConnectionRegistry[keyof TnlConnectionRegistry];
export interface TnlGroupClient {
  connect(name: string): TnlConnectionHandle<Settings>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

export function groupClient(options: TnlGroupClientOptions): TnlGroupClient {
  const parsed = parseValue(
    z.strictObject({
      connection: connectionSchema,
      workload: z.strictObject({
        name: serviceNameSchema,
        token: z.custom<() => Promise<string>>((value) => typeof value === "function"),
      }),
    }),
    options,
    "sdk.configuration_invalid",
  );
  const connection = parsed.connection;
  const { name, token } = parsed.workload;
  const policy = Object.hasOwn(connection.workloads, name) ? connection.workloads[name] : undefined;
  if (policy === undefined) throw new TnlError("sdk.workload_required");
  if (policy.services.some((service) => !Object.hasOwn(connection.services, service)))
    throw new TnlError("sdk.configuration_invalid");
  const manifest = {
    schema: 1,
    server: connection.server,
    team: connection.team_id,
    project_key: connection.project_key,
    project_label: connection.project_label,
    source_fingerprint: connection.source_fingerprint,
    publisher_group_id: connection.group_id,
    services: connection.services,
    workloads: {
      [name]: { ...policy, acquisition: { method: "callback", audience: connection.server } },
    },
  };
  // capture selection once. concurrent clients never change process cwd, global
  // provider callbacks, environment variables or module-wide project metadata.
  const directory = process.cwd();
  let files: Promise<{ directory: string; filename: string }> | undefined;
  let temporary: string | undefined;
  let closing: Promise<void> | undefined;
  const scope: ConnectionScope = {
    key: randomUUID(),
    natives: new Set(),
    fetches: new Map(),
    pending: new Set(),
    closed: false,
    async selection() {
      files ??= (async () => {
        temporary = await mkdtemp(path.join(tmpdir(), "tnl-group-client-"));
        const filename = path.join(temporary, "workloads.json");
        await writeFile(filename, JSON.stringify(manifest), { mode: 0o600, flag: "wx" });
        return { directory: await realpath(directory), filename };
      })();
      return { ...(await files), name };
    },
    async assertion() {
      const signal = AbortSignal.timeout(10_000);
      try {
        return boundedAssertion(await cancellable(signal, token));
      } catch (error) {
        throw privateTnlError("sdk.workload_assertion_unavailable", error);
      }
    },
  };
  const beforeExit = () => {
    void close().catch(() => {});
  };
  const close = (): Promise<void> => {
    closing ??= (async () => {
      await closeConnectionScope(scope);
      if (temporary !== undefined) await rm(temporary, { recursive: true });
      process.off("beforeExit", beforeExit);
    })().catch((error: unknown) => {
      closing = undefined;
      throw error;
    });
    return closing;
  };
  process.once("beforeExit", beforeExit);
  return Object.freeze({
    connect(service: string) {
      if (scope.closed) throw new TnlError("sdk.connection_unavailable");
      if (!policy.services.includes(service)) throw new TnlError("sdk.workload_denied");
      return connectionHandle(service, () => {}, scope);
    },
    close,
    [Symbol.asyncDispose]: close,
  });
}
