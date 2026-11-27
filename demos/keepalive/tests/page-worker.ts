// fixture for the page/worker boundary; no relay, control or certificate requests.
import "../src/validation.ts";
import { hostCommand } from "../src/hosting/messages.ts";
import { STARTUP_MS } from "../src/policy.ts";
import { PULSE_SECONDS } from "../src/hosting/activity.ts";
import { pageHost } from "./page-host.ts";

self.onmessage = ({ data }: MessageEvent<unknown>) => {
  const command = hostCommand.parse(data);
  if (command.type === "stop") {
    self.postMessage({ type: "stopped", expired: false, requests: 7 });
    return;
  }
  const host = command.firstHostToContact ?? (command.bootstrap ? pageHost : undefined);
  if (host === undefined || command.name !== "quiet-pine")
    throw new Error("The page lost its invitation or saved host name.");
  const since = command.startupEndsAt - STARTUP_MS + 2_000;
  self.postMessage({
    type: "hosting",
    origin: host.origin,
    runID: host.runID,
    since,
    endsAt: since + 15 * 60_000,
    startedAt: since - 60_000,
    hosts: 3,
    tabs: 12,
    localTabs: 4,
    saturated: false,
  });
  self.postMessage({
    type: "activity",
    second: Math.floor(since / 1_000),
    pulse: "_".repeat(PULSE_SECONDS - 1) + "|",
    requests: 7,
  });
};
