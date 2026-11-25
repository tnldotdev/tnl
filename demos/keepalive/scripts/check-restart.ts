import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { resolve, join } from "node:path";
import { tmpdir } from "node:os";
import { parseArgs } from "node:util";
import { chromium } from "playwright";
import { fleets } from "../src/fleets.ts";
import { verifyRestart } from "../tests/restart.ts";

const { values } = parseArgs({
  options: {
    release: { type: "string" },
    "profile-dir": { type: "string" },
  },
});
assert(values.release && /^[a-f0-9]{64}$/.test(values.release), "pass the expected --release ID");
assert(values["profile-dir"], "pass a private --profile-dir for the ramp seed");
const profile = resolve(values["profile-dir"], "keepalive-ramp");
await mkdir(profile, { recursive: true, mode: 0o700 });
const fresh = await mkdtemp(join(tmpdir(), "keepalive-volunteer-"));
const open = (path: string) => chromium.launchPersistentContext(path, { channel: "chrome" });
try {
  await verifyRestart({
    site: `https://${fleets.ramp.site}`,
    start: `https://${fleets.ramp.start}`,
    parent: fleets.ramp.parent,
    control: "https://control.tnl.dev",
    releaseID: values.release,
    openSeed: () => open(profile),
    openVolunteer: () => open(fresh),
    emit: (event, data) => console.log(JSON.stringify({ event, ...data })),
  });
} finally {
  await rm(fresh, { recursive: true, force: true });
}
