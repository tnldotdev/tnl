import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { test } from "vitest";
import { applyFault, type FaultRuntime } from "./runtime-faults.ts";

function faultRuntime(overrides: Partial<FaultRuntime>): FaultRuntime {
  return {
    compose: () => "",
    inspect: () => ({
      State: { Running: false, ExitCode: 137 },
      NetworkSettings: { Networks: { local: { IPAddress: "192.0.2.1" } } },
    }),
    readEvent: async () => true,
    event: async () => {},
    sleep: async () => {},
    results: tmpdir(),
    ingresses: ["ingress-a"],
    activePublishers: ["publishers"],
    network: { path: "forwarding", rtt: "20ms", loss: "0.1", seed: "0" },
    state: { intentionalRelayExit: false },
    ...overrides,
  };
}

test("relay kill is acknowledged before the lease wait and cleared after restart", async () => {
  const steps: string[] = [];
  const state = { intentionalRelayExit: false };
  const runtime = faultRuntime({
    state,
    compose: (args) => {
      steps.push(args[0] ?? "");
      if (args[0] === "kill") assert.equal(state.intentionalRelayExit, true);
      return "";
    },
    event: async (name) => {
      steps.push(name);
    },
    sleep: async (ms) => {
      assert.equal(ms, 31_000);
      assert.equal(state.intentionalRelayExit, true);
      steps.push("lease wait");
    },
  });

  await applyFault("relay-kill", runtime);

  assert.deepEqual(steps, ["kill", "fault.applied", "lease wait", "start", "fault.restored"]);
  assert.equal(state.intentionalRelayExit, false);
});

test("a partial blackhole restores applied rules and retains cleanup failures", async () => {
  const commands: string[] = [];
  const events: string[] = [];
  const runtime = faultRuntime({
    compose: (args) => {
      const command = `${args[4]} ${args[9]}`;
      commands.push(command);
      if (command === "-I udp") throw new Error("install failed");
      if (command === "-D tcp") throw new Error("undo failed");
      return "";
    },
    event: async (name) => {
      events.push(name);
    },
  });

  await assert.rejects(applyFault("publisher-blackhole", runtime), (error: unknown) => {
    assert(error instanceof AggregateError);
    assert.deepEqual(error.errors.map(String), ["Error: install failed", "Error: undo failed"]);
    return true;
  });
  assert.deepEqual(commands, ["-I tcp", "-I udp", "-D tcp"]);
  assert.deepEqual(events, []);
});
