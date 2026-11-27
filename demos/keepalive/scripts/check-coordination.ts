import { parseArgs } from "node:util";
import { open, readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { openSync, closeSync, writeFileSync } from "node:fs";
import {
  simulateCoordination,
  type CoordinationScenario,
  type CoordinationSettings,
} from "../tests/coordination.ts";

const { values } = parseArgs({
  options: {
    hosts: { type: "string", default: "500" },
    minutes: { type: "string", default: "10" },
    seed: { type: "string", default: "1" },
    scenario: { type: "string", default: "growth" },
    "latency-ms": { type: "string", default: "20" },
    loss: { type: "string", default: "0" },
    discovery: { type: "string", default: "shared" },
    departure: { type: "string", default: "current" },
    policy: { type: "string", default: "visitors" },
    "reader-bytes-per-second": { type: "string" },
    "safe-bytes-per-host": { type: "string" },
    report: { type: "string" },
  },
});
const scenario = values.scenario;
if (
  scenario !== "growth" &&
  scenario !== "loss" &&
  scenario !== "partition" &&
  scenario !== "turnover"
)
  throw new Error("scenario must be growth, loss, partition, or turnover");
const discovery = values.discovery;
if (discovery !== "shared" && discovery !== "none")
  throw new Error("discovery must be shared or none");
const departure = values.departure;
if (departure !== "current" && departure !== "insertion")
  throw new Error("departure must be current or insertion");
const policy = values.policy;
if (policy !== "visitors" && policy !== "capacity")
  throw new Error("policy must be visitors or capacity");
const report = values.report ? await open(values.report, "wx", 0o600) : undefined;
let checkpoints: number | undefined;
const failures: unknown[] = [];
function checkpoint(value: Record<string, unknown>) {
  if (checkpoints !== undefined)
    writeFileSync(checkpoints, JSON.stringify({ schema: 1, ...value }) + "\n");
}
try {
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const sourceFiles = [
    "./check-coordination.ts",
    "../tests/coordination.ts",
    "../tests/recruitment.ts",
    "../tests/measure.ts",
    "../src/peers/gossip.ts",
    "../src/peers/host.ts",
    "../src/peers/presence.ts",
    "../src/peers/report.ts",
    "../src/policy.ts",
  ];
  const { createHash } = await import("node:crypto");
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
  const settings: CoordinationSettings = {
    hosts: Number(values.hosts),
    durationMs: Number(values.minutes) * 60_000,
    seed: Number(values.seed),
    scenario: scenario satisfies CoordinationScenario,
    latencyMs: Number(values["latency-ms"]),
    loss: Number(values.loss),
    discovery,
    departure,
    policy,
    ...(values["reader-bytes-per-second"] === undefined
      ? {}
      : { readerBytesPerSecond: Number(values["reader-bytes-per-second"]) }),
    ...(values["safe-bytes-per-host"] === undefined
      ? {}
      : { safeBytesPerSecondPerHost: Number(values["safe-bytes-per-host"]) }),
  };
  if (values.report) checkpoints = openSync(`${values.report}.checkpoints.ndjson`, "wx", 0o600);
  checkpoint({ event: "start", commit, sourceHashes, settings });
  const began = performance.now();
  const result = await simulateCoordination(settings, (sample) => {
    checkpoint({ event: "sample", ...sample, heapUsedBytes: process.memoryUsage().heapUsed });
  });
  const line =
    JSON.stringify({
      schema: 1,
      commit,
      sourceHashes,
      elapsedRealMs: Math.round(performance.now() - began),
      ...result,
    }) + "\n";
  if (report) await report.writeFile(line);
  else process.stdout.write(line);
  checkpoint({
    event: "end",
    outcome: result.outcome,
    simulatedMs: result.simulatedMs,
    harness: result.harness,
  });
  const last = result.samples.at(-1);
  console.error(
    `${scenario} (${result.outcome}): ${result.joins} joins, ${result.departures} departures, ` +
      `${result.failedRequests}/${result.requests} failed exchanges; ` +
      `final online ${last?.online}, median roster coverage ${last?.rosterCoverage.p50}, ` +
      `median audience coverage ${last?.freshAudienceCoverage.p50}`,
  );
  if (result.outcome !== "completed") process.exitCode = 1;
} catch (error) {
  failures.push(error);
  try {
    checkpoint({ event: "error", kind: error instanceof Error ? error.name : "unknown" });
  } catch (recordingError) {
    failures.push(recordingError);
  }
} finally {
  try {
    if (checkpoints !== undefined) closeSync(checkpoints);
  } catch (error) {
    failures.push(error);
  }
  try {
    await report?.close();
  } catch (error) {
    failures.push(error);
  }
}
if (failures.length) throw new AggregateError(failures, "coordination run or recording failed");
