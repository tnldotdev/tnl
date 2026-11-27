// opt-in process proof: low heap pressure must leave a failed, readable report.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as z from "zod/mini";

const directory = await mkdtemp(join(tmpdir(), "keepalive-coordination-"));
const outcome = z.enum(["completed", "recruitment_limit", "harness_memory_limit"]);
const reportSchema = z.object({
  outcome,
  joins: z.number(),
  harness: z.object({ retiredViewsRetained: z.number() }),
  samples: z.array(z.object({ joins: z.number(), online: z.number(), retainedViews: z.number() })),
});
const checkpointSchema = z.object({
  event: z.enum(["start", "sample", "end", "error"]),
  outcome: z.optional(outcome),
});

async function run(name: string, hosts: number, minutes: number, bounded: boolean) {
  const path = join(directory, `${name}.json`);
  const child = spawn(
    process.execPath,
    [
      "--max-old-space-size=96",
      "demos/keepalive/scripts/check-coordination.ts",
      "--hosts",
      String(hosts),
      "--minutes",
      String(minutes),
      "--scenario",
      "growth",
      "--report",
      path,
    ],
    { stdio: "inherit", timeout: 60_000 },
  );
  const [code, signal] = await once(child, "exit");
  assert.equal(signal, null, "coordination process crashed or exceeded its deadline");
  assert.equal(code, bounded ? 1 : 0, "unexpected coordination task outcome");
  const report = reportSchema.parse(JSON.parse(await readFile(path, "utf8")));
  assert.equal(report.outcome, bounded ? "harness_memory_limit" : "completed");
  assert.equal(report.harness.retiredViewsRetained, 0);
  assert.equal(report.joins, report.samples.at(-1)?.joins);
  assert(report.samples.every((sample) => sample.retainedViews === sample.online));
  const checkpoints = (await readFile(`${path}.checkpoints.ndjson`, "utf8"))
    .trim()
    .split("\n")
    .map((line) => checkpointSchema.parse(JSON.parse(line)));
  assert.equal(checkpoints[0]?.event, "start");
  assert.equal(checkpoints.at(-1)?.event, "end");
  assert.equal(checkpoints.at(-1)?.outcome, report.outcome);
  assert.equal(checkpoints.filter((row) => row.event === "sample").length, report.samples.length);
}

await run("completed", 3, 1, false);
await run("bounded", 500, 10, true);
console.log(`coordination task verified complete and memory-bounded reports: ${directory}`);
