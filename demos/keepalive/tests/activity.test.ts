import { expect, it } from "vitest";
import { PULSE_SECONDS, RequestActivity, requestPulse } from "../src/hosting/activity.ts";

const quiet = "_".repeat(PULSE_SECONDS);

it("marks active seconds, counts bursts, and ignores unsuccessful responses", () => {
  const activity = new RequestActivity();
  activity.record(new Response(null, { status: 404 }), 1_000);
  activity.record(new Response("one"), 2_000);
  activity.record(new Response("two"), 2_500);
  activity.record(new Response("three"), 4_000);
  expect(activity.snapshot(4_000)).toEqual({
    second: 4,
    pulse: quiet.slice(3) + "|_|",
    requests: 3,
  });
});

it("ages delayed pulses without losing the total and starts each turn at zero", () => {
  const activity = new RequestActivity();
  activity.record(new Response("file"), 2_000);
  const { pulse, second } = activity.snapshot(2_000);
  expect(requestPulse(pulse, second, 3_000)).toBe(quiet.slice(2) + "|_");
  expect(requestPulse(pulse, second, 65_000)).toBe(quiet);
  expect(activity.snapshot(65_000)).toEqual({ second: 65, pulse: quiet, requests: 1 });
  expect(new RequestActivity().snapshot(65_000)).toEqual({ second: 65, pulse: quiet, requests: 0 });
});
