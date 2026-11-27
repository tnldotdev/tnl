import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { open, readFile } from "node:fs/promises";
import { monitorEventLoopDelay } from "node:perf_hooks";
import { parseArgs } from "node:util";
import { fleets } from "../src/fleets.ts";
import { hostOrigin, runIDSchema } from "../src/peers/host.ts";
import { parseRelease, readBytes } from "../src/release.ts";
import { runArrivals } from "../tests/arrivals.ts";
import { readerConnections, readerOpen } from "../tests/reader-load.ts";
import { periodic } from "../tests/measure.ts";
import { observeInfrastructure } from "../tests/infra-samples.ts";

const { values } = parseArgs({
  options: {
    site: { type: "string" },
    target: { type: "string" },
    run: { type: "string" },
    manifest: { type: "string" },
    release: { type: "string" },
    report: { type: "string" },
    rates: { type: "string", default: "1,5,10" },
    seconds: { type: "string", default: "60" },
    concurrency: { type: "string", default: "128" },
    connections: { type: "string", default: "fresh" },
    workload: { type: "string", default: "page" },
    metrics: { type: "string" },
    "allow-ramp-load": { type: "boolean", default: false },
  },
});
assert(
  values.site && values.manifest && values.release && values.report,
  "pass --site, --manifest, --release, and a new --report path",
);
const site = new URL(values.site);
const local = site.protocol === "http:" && ["127.0.0.1", "[::1]"].includes(site.hostname);
assert(
  local || (values["allow-ramp-load"] && site.origin === `https://${fleets.ramp.site}`),
  "only loopback or an explicitly approved ramp origin is allowed",
);
assert.equal(site.href, site.origin + "/", "site must be an origin");
const target = new URL(values.target ?? site);
assert.equal(target.href, target.origin + "/", "target must be an origin");
assert(
  target.origin === site.origin ||
    (!local && hostOrigin(target.origin, fleets.ramp.parent) && values.run),
  "a direct target needs an exact ramp hostname and --run",
);
if (values.run) runIDSchema.parse(values.run);
const rates = values.rates.split(",").map(Number);
const seconds = Number(values.seconds);
const concurrency = Number(values.concurrency);
assert(
  rates.length >= 1 &&
    rates.length <= 10 &&
    rates.every((rate) => Number.isFinite(rate) && rate > 0 && rate <= (local ? 1_000 : 10)),
  "shared-backend runs are capped at 10 arrivals/s; higher rates need an isolated backend harness",
);
assert(
  Number.isInteger(seconds) && seconds >= 1 && seconds <= 300 && seconds * rates.length <= 1_800,
  "stages must be 1–300 seconds, at most 30 minutes total",
);
assert(
  Number.isSafeInteger(concurrency) && concurrency >= 1 && concurrency <= 512,
  "concurrency must be 1–512",
);
assert(["fresh", "reuse"].includes(values.connections), "connections must be fresh or reuse");
assert(["page", "connection"].includes(values.workload), "workload must be page or connection");
const manifest: unknown = JSON.parse(await readFile(values.manifest, "utf8"));
const release = await parseRelease(manifest);
assert.equal(release.id, values.release, "release pin does not match the manifest");
const html = release.assets.find((asset) => asset.path === "/index.html");
const script = release.assets.find((asset) => asset.path === "/app.js");
assert(html && script, "manifest must pin HTML and JavaScript");
const assets = values.workload === "page" ? [html, script] : [html];
const report = await open(values.report, "wx", 0o600);
const run = randomUUID();
const abort = new AbortController();
const connections = readerConnections(values.connections === "reuse", concurrency);
const lag = monitorEventLoopDelay({ resolution: 20 });
const stops: (() => Promise<void>)[] = [];
const failures: unknown[] = [];
let stage = -1;
let incomplete = false;
let passed = true;
let events = 0;
// writes are serialized and awaited before close; a write failure aborts new
// load rather than allowing a run with silently missing observations.
let writes = Promise.resolve();
function emit(event: string, fields: Record<string, unknown>) {
  const row = JSON.stringify({ schema: 1, run, at: Date.now(), stage, event, ...fields }) + "\n";
  events++;
  writes = writes.then(async () => {
    await report.writeFile(row);
  });
  void writes.catch((error: unknown) => {
    failures.push(error);
    abort.abort();
  });
}
const interrupt = () => {
  incomplete = true;
  abort.abort();
};
process.once("SIGINT", interrupt);
process.once("SIGTERM", interrupt);
async function health() {
  const signal = AbortSignal.any([abort.signal, AbortSignal.timeout(6_000)]);
  const response = await fetch(
    "https://probe.uptime.tnl-dev-deploy-uptime.deploy.oval-walnut.tnl.dev/index.html",
    { signal, redirect: "error", cache: "no-store" },
  );
  const body = new TextDecoder().decode(await readBytes(response, 1_024, signal));
  assert(
    response.status === 200 && body.trim() === "tnl-uptime-origin-ok",
    "independent tunnel is unhealthy",
  );
}
try {
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const sourceFiles = [
    "./check-reader-load.ts",
    "../tests/arrivals.ts",
    "../tests/reader-load.ts",
    "../tests/measure.ts",
    "../src/release.ts",
    "../src/network.ts",
  ];
  const sourceHashes = Object.fromEntries(
    await Promise.all(
      sourceFiles.map(async (path) => [
        path,
        createHash("sha256")
          .update(await readFile(new URL(path, import.meta.url)))
          .digest("hex"),
      ]),
    ),
  );
  emit("start", {
    commit,
    sourceHashes,
    release,
    target: target.origin,
    expectedRunID: values.run ?? null,
    rates,
    seconds,
    concurrency,
    connections: values.connections,
    workload: values.workload,
    limitations: [
      "HTTP/1.1 generator; not a browser rendering or HTTP/2 result",
      "attaches to existing hosts; does not own fleet startup or teardown",
      "shared production backend; no saturation or server fault injection",
    ],
  });
  if (!local) {
    await health();
    stops.push(
      periodic(
        5_000,
        async () => {
          try {
            await health();
            emit("independent_tunnel", { ok: true });
          } catch {
            if (abort.signal.aborted) return;
            emit("independent_tunnel", { ok: false });
            incomplete = true;
            abort.abort();
          }
        },
        (slots) => emit("health_skipped", { slots }),
      ),
    );
  }
  if (values.metrics) stops.push(await observeInfrastructure(values.metrics, emit));
  let cpu = process.cpuUsage();
  let sampledAt = performance.now();
  lag.enable();
  stops.push(
    periodic(
      5_000,
      async () => {
        const elapsed = performance.now() - sampledAt;
        const next = process.cpuUsage();
        emit("generator", {
          memory: process.memoryUsage(),
          cpuCores:
            elapsed > 0
              ? (next.user + next.system - cpu.user - cpu.system) / (elapsed * 1_000)
              : null,
          eventLoopP99Ms: lag.percentile(99) / 1_000_000,
        });
        cpu = next;
        sampledAt = performance.now();
        lag.reset();
      },
      (slots) => emit("generator_skipped", { slots }),
    ),
  );
  for (const [index, rate] of rates.entries()) {
    if (abort.signal.aborted) break;
    stage = index;
    emit("stage_start", { rate, durationMs: seconds * 1_000 });
    const result = await runArrivals({
      rate,
      durationMs: seconds * 1_000,
      concurrency,
      signal: abort.signal,
      issue: async (slot, signal) =>
        readerOpen(
          connections,
          target,
          assets,
          signal,
          (sample) => emit("transfer", { slot, ...sample }),
          values.run,
        ),
      record: (sample) => emit("arrival", { ...sample }),
    });
    emit("stage_result", { rate, ...result });
    passed &&= result.successFraction >= 0.99;
    console.error(
      `${rate}/s: ${result.successful}/${result.scheduled} verified within 6 s; ` +
        `p95 ${result.successfulLatencyMs.p95?.toFixed(0) ?? "unknown"} ms, ` +
        `skipped ${Object.values(result.skipped).reduce((a, b) => a + b, 0)}`,
    );
  }
} catch (error) {
  failures.push(error);
} finally {
  abort.abort();
  const results = await Promise.allSettled(stops.map((stop) => stop()));
  for (const result of results) if (result.status === "rejected") failures.push(result.reason);
  lag.disable();
  connections.close();
  process.off("SIGINT", interrupt);
  process.off("SIGTERM", interrupt);
  emit("end", { complete: !incomplete && failures.length === 0, passed, events });
  try {
    await writes;
  } catch (error) {
    failures.push(error);
  }
  await report.close();
}
if (failures.length) throw new AggregateError(failures, "reader load failed");
if (incomplete || !passed) process.exitCode = 1;
