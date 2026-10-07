import { spawn, execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import * as z from "zod";
import { parseJSON, parseValue } from "./validation.ts";

const optionsSchema = z.object({
  server: z
    .url()
    .refine(
      (server) => new URL(server).protocol === "https:" && new URL(server).origin === server,
      "server must be a canonical HTTPS origin",
    ),
  team: z.string().min(1),
  stateDir: z.string().refine(isAbsolute, "state directory must be absolute"),
  tnlBinary: z.string().refine(isAbsolute, "tnl binary path must be absolute"),
  version: z.string().min(1),
  claimedDomain: z.union([
    z.literal(""),
    z.string().regex(/^(?:[a-z0-9]+(?:-[a-z0-9]+)*\.)+[a-z0-9]+(?:-[a-z0-9]+)*$/),
  ]),
});
type Options = z.infer<typeof optionsSchema>;

type Ready = { url: string; publishRunNumber: number; tunnelID: string };

const publishEventSchema = z.looseObject({
  schema_version: z.literal(1),
  type: z.string(),
  code: z.string().optional(),
  message: z.string().optional(),
});
const readySchema = publishEventSchema.extend({
  type: z.literal("ready"),
  url: z.url(),
  tunnel_id: z.string().min(1),
  publish_run_number: z.int().positive(),
});
const statusSchema = z.object({
  tunnels: z.array(
    z.object({
      tunnel_id: z.string(),
      server: z.string(),
      public_url_id: z.string().optional(),
    }),
  ),
});
const visitorSchema = z.object({ host: z.string(), nonce: z.string() });

export function readyEvent(line: string): Ready | undefined {
  const event = parseJSON(line, publishEventSchema, "tnl publish event");
  if (event.type === "error") {
    throw new Error(`tnl publish: ${event.code ?? event.message ?? "unknown error"}`);
  }
  if (event.type !== "ready") return undefined;
  const ready = parseValue(event, readySchema, "tnl ready event");
  return {
    url: ready.url,
    tunnelID: ready.tunnel_id,
    publishRunNumber: ready.publish_run_number,
  };
}

export function publicURLID(snapshot: unknown, tunnelID: string, server: string): string {
  const { tunnels } = parseValue(snapshot, statusSchema, "tnl status result");
  const id = tunnels.find(
    (value) => value.tunnel_id === tunnelID && value.server === server,
  )?.public_url_id;
  if (!id) {
    throw new Error("tnl status has no public URL ID for this tunnel");
  }
  return id;
}

function options(args: string[]): { mode: "plan" | "run"; config: Options } {
  const { positionals, values } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      server: { type: "string" },
      team: { type: "string" },
      "state-dir": { type: "string" },
      "tnl-binary": { type: "string" },
      version: { type: "string" },
      "claimed-domain": { type: "string" },
    },
  });
  const [mode] = positionals;
  if (positionals.length !== 1 || (mode !== "plan" && mode !== "run")) {
    throw new Error("usage: release-check.ts plan|run [flags]");
  }
  const config = parseValue(
    {
      server: values.server ?? "",
      team: values.team ?? "",
      stateDir: values["state-dir"] ?? "",
      tnlBinary: values["tnl-binary"] ?? "",
      version: values.version ?? "",
      claimedDomain: values["claimed-domain"] ?? "",
    },
    optionsSchema,
    "release check options",
  );
  return { mode, config };
}

function cli(config: Options, cwd: string, ...args: string[]): string {
  return execFileSync(config.tnlBinary, ["--no-config", "--no-telemetry", ...args], {
    cwd,
    encoding: "utf8",
    timeout: 20_000,
    maxBuffer: 1 << 20,
  });
}

function publisher(config: Options, cwd: string, target: string, flags: string[]) {
  const child = spawn(
    config.tnlBinary,
    [
      "--no-config",
      "--no-telemetry",
      "publish",
      target,
      `--server=${config.server}`,
      `--state-dir=${config.stateDir}`,
      `--team=${config.team}`,
      "--output=ndjson",
      ...flags,
    ],
    { cwd, stdio: ["ignore", "pipe", "pipe"] },
  );
  const stdout = child.stdout;
  if (!stdout || !child.stderr) throw new Error("tnl publish has no output stream");
  let diagnostics = "";
  child.stderr.on("data", (chunk: Buffer) => {
    diagnostics = (diagnostics + chunk.toString()).slice(-2048);
  });
  const done = new Promise<number>((resolve) => child.once("close", (code) => resolve(code ?? 1)));
  const ready = new Promise<Ready>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("tnl publish did not become ready in 5 minutes")),
      5 * 60_000,
    );
    const finish = (value: Ready | Error) => {
      clearTimeout(timer);
      if (value instanceof Error) reject(value);
      else resolve(value);
    };
    child.once("error", (error) => finish(error));
    child.once("close", (code) => finish(new Error(`tnl publish exited ${code}: ${diagnostics}`)));
    createInterface({ input: stdout }).on("line", (line) => {
      try {
        const event = readyEvent(line);
        if (event) finish(event);
      } catch (error) {
        finish(error instanceof Error ? error : new Error("invalid publisher event"));
      }
    });
  });
  return {
    ready,
    async stop() {
      if (child.exitCode !== null)
        throw new Error(`tnl publish exited before stopping: ${diagnostics}`);
      child.kill("SIGINT");
      const timer = setTimeout(() => child.kill("SIGKILL"), 20_000);
      const code = await done;
      clearTimeout(timer);
      if (code !== 0) throw new Error(`tnl publish exited ${code}: ${diagnostics}`);
    },
  };
}

export async function visit(url: string, nonce: string): Promise<void> {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || parsed.pathname !== "/")
    throw new Error(`invalid public URL ${url}`);
  const deadline = Date.now() + 120_000;
  for (;;) {
    let response: Response;
    try {
      response = await fetch(new URL(`/release-check/${nonce}`, parsed), {
        redirect: "manual",
        signal: AbortSignal.timeout(10_000),
      });
    } catch (error) {
      if (Date.now() >= deadline) throw error;
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      continue;
    }
    if (response.status !== 200) throw new Error(`visitor HTTP ${response.status}`);
    const value = parseValue(await response.json(), visitorSchema, "local service response");
    if (value.host !== parsed.host || value.nonce !== nonce)
      throw new Error("visitor reached the wrong local service");
    return;
  }
}

async function main(): Promise<void> {
  const { mode, config } = options(process.argv.slice(2));
  if (mode === "plan") {
    console.log(
      JSON.stringify({
        server: config.server,
        team: config.team,
        version: config.version,
        checks: [
          "generated ephemeral URL",
          "saved URL republish",
          ...(config.claimedDomain ? ["claimed-domain shared URL"] : []),
        ],
        read_only: true,
      }),
    );
    return;
  }
  const version = cli(config, process.cwd(), "version").trim();
  if (!version.startsWith(`tnl ${config.version} (`))
    throw new Error(`unexpected tnl version: ${version}`);
  const cwd = await mkdtemp(join(tmpdir(), "tnl-release-check-"));
  const nonce = randomBytes(8).toString("hex");
  const label = `releasecheck-${randomBytes(10).toString("hex")}`;
  const shared = `${label}.${config.claimedDomain}`;
  const server = createServer((request, response) => {
    if (request.url !== `/release-check/${nonce}`) {
      response.writeHead(404).end();
      return;
    }
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ host: request.headers.host, nonce }));
  });
  let savedID: string | undefined;
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    cli(
      config,
      cwd,
      "team",
      "use",
      config.team,
      `--server=${config.server}`,
      `--state-dir=${config.stateDir}`,
    );
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("local service did not listen");
    const target = `http://127.0.0.1:${address.port}`;
    async function check(
      name: string,
      flags: string[],
      inspect?: (ready: Ready) => void,
    ): Promise<Ready> {
      const process = publisher(config, cwd, target, flags);
      let failure: unknown;
      let ready: Ready | undefined;
      try {
        ready = await process.ready;
        inspect?.(ready);
        await visit(ready.url, nonce);
      } catch (error) {
        failure = error;
      }
      try {
        await process.stop();
      } catch (error) {
        failure ??= error;
      }
      if (failure) throw failure;
      if (!ready) throw new Error("publisher did not report a public URL");
      console.log(`${name}: passed (${ready.url})`);
      return ready;
    }
    await check("generated ephemeral URL", ["--ephemeral"]);
    const savedFlags = [`--name=${label}`];
    const first = await check("saved public URL", savedFlags, (ready) => {
      const status = parseJSON(
        cli(config, cwd, "status", "--all", "--output=json", `--state-dir=${config.stateDir}`),
        statusSchema,
        "tnl status result",
      );
      savedID = publicURLID(status, ready.tunnelID, config.server);
    });
    const second = await check("republished public URL", savedFlags, (ready) => {
      const status = parseJSON(
        cli(config, cwd, "status", "--all", "--output=json", `--state-dir=${config.stateDir}`),
        statusSchema,
        "tnl status result",
      );
      if (
        publicURLID(status, ready.tunnelID, config.server) !== savedID ||
        ready.url !== first.url ||
        ready.publishRunNumber <= first.publishRunNumber
      ) {
        throw new Error(
          "saved public URL did not retain its ID and advance its publish run number",
        );
      }
    });
    if (second.url !== first.url) throw new Error("saved public URL hostname changed");
    if (config.claimedDomain)
      await check(
        "shared custom URL",
        ["--ephemeral", `--public-url=https://${shared}`],
        (ready) => {
          if (ready.url !== `https://${shared}`)
            throw new Error("custom public URL hostname changed");
        },
      );
  } finally {
    try {
      if (savedID)
        cli(
          config,
          cwd,
          "url",
          "delete",
          savedID,
          `--server=${config.server}`,
          `--state-dir=${config.stateDir}`,
        );
    } finally {
      if (server.listening) await new Promise<void>((resolve) => server.close(() => resolve()));
      await rm(cwd, { recursive: true, force: true });
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error: unknown) => {
    console.error(safeToolMessage(error, "tool.validation_failed"));
    process.exitCode = 1;
  });
}
import { installToolFailureHandler, safeToolMessage } from "./errors.ts";
installToolFailureHandler(import.meta, "tool.validation_failed");
