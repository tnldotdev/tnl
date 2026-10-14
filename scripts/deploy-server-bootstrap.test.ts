import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

const flyctl = String.raw`#!/usr/bin/env node
const fs = require("node:fs");
const args = process.argv.slice(2);
const file = process.env.FAKE_FLY_STATE;
const state = JSON.parse(fs.readFileSync(file, "utf8"));
const option = (name) => args[args.indexOf(name) + 1];
const app = option("--app");
const role = app && app.replace(/^tnl-/, "").replace(/-staging$/, "");
const save = () => fs.writeFileSync(file, JSON.stringify(state));
const json = (data) => process.stdout.write(JSON.stringify(data));
state.commands.push(args[0] + " " + (args[1] || "") + (args[0] === "machine" && ["update", "start"].includes(args[1]) ? " " + app : ""));
if (args[0] === "apps" && args[1] === "list") json(state.apps.map((Name) => ({Name})));
else if (args[0] === "apps" && args[1] === "create") state.apps.push(args[2]);
else if (args[0] === "ips" && args[1] === "list") json((state.ips[app] || []).map((Type) => ({Type})));
else if (args[0] === "ips" && args[1].startsWith("allocate-")) (state.ips[app] ||= []).push(args[1].replace("allocate-", ""));
else if (args[0] === "secrets" && args[1] === "list") json(["TNLD_CLUSTER_SECRET", "TNLD_STORAGE_KEY", "TNLD_DATABASE_URL"].map((name) => ({name})));
else if (args[0] === "config" && args[1] === "show") {
  const name = option("--config").match(/fly\.(tnl-[^.]+)\.toml$/)[1];
  const selectedRole = name.replace(/^tnl-/, "").replace(/-staging$/, "");
  const proxy = (port) => ({ ...port, handlers: ["proxy_proto"], proxy_proto_options: {version: "v2"} });
  const tcp = { protocol: "tcp", internal_port: 8443, ports: selectedRole === "ingress"
    ? [proxy({port: 443}), proxy({port: 3306}), proxy({port: 5432}), proxy({start_port: 10000, end_port: 10031})]
    : [{port: 443}], processes: ["app", "udp"] };
  json({ app: name, primary_region: "sjc", kill_signal: "SIGTERM", kill_timeout: 45,
    env: selectedRole.startsWith("relay-") ? {TNLD_ROLE: "relay", TNLD_RELAY_SERVICE_ID: selectedRole} :
      selectedRole === "ingress" ? {TNLD_ROLE: "ingress", TNLD_INGRESS_ID: "ingress-1", TNLD_INGRESS_POOL_ID: "ingress-a"} : {TNLD_ROLE: "control"},
    metrics: [{port: 9090, path: "/metrics"}],
    services: selectedRole.startsWith("relay-") ? [tcp, {protocol: "udp", internal_port: 443, ports: [{port: 443}], processes: ["udp"]}] : [tcp],
    vm: [{cpu_kind: "shared", cpus: 1, memory: "512mb"}],
    processes: selectedRole.startsWith("relay-") ? {app: "serve", udp: "serve"} : undefined });
} else if (args[0] === "config" && args[1] === "validate") { /* valid fixture */ }
else if (args[0] === "machine" && args[1] === "list") json(state.machines[app] || []);
else if (args[0] === "machine" && args[1] === "create") {
  const config = JSON.parse(option("--machine-config"));
  const id = (++state.next).toString(16).padStart(14, "0");
  (state.machines[app] ||= []).push({id, state: "stopped", checks: [{status: "passing"}], image_ref: {digest: process.env.FAKE_DIGEST}, config});
} else if (args[0] === "machine" && args[1] === "update") {
  const machine = state.machines[app].find((item) => item.id === args[2]);
  if (args.includes("--env")) {
    const [name, ...value] = option("--env").split("=");
    machine.config.env[name] = value.join("=");
  } else machine.config = JSON.parse(option("--machine-config"));
  machine.image_ref.digest = process.env.FAKE_DIGEST;
} else if (args[0] === "machine" && args[1] === "start") {
  state.machines[app].find((item) => item.id === args[2]).state = "started";
} else if (args[0] === "machine" && args[1] === "wait") { /* settled fixture */ }
else throw Error("unexpected Fly command: " + args.join(" "));
save();
`;

const docker = String.raw`#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === "run" && args.at(-1) === "version")
  process.stdout.write("tnld " + (process.env.FAKE_VERSION || "main") + "-" + process.env.FAKE_COMMIT + " (" + process.env.FAKE_COMMIT + ")\n");
else if (args[0] === "run" && args.at(-1) === "migrate") { /* migrated fixture */ }
else if (args[0] === "buildx")
  process.stdout.write(JSON.stringify({manifests: [{digest: process.env.FAKE_DIGEST, platform: {os: "linux", architecture: "amd64"}}]}));
else throw Error("unexpected Docker command");
`;

test("an empty Fly organization gets the configured topology and can be deployed again", () => {
  const directory = mkdtempSync(join(tmpdir(), "tnl-fly-bootstrap-"));
  try {
    const stateFile = join(directory, "state.json");
    writeFileSync(
      stateFile,
      JSON.stringify({ apps: [], ips: {}, machines: {}, next: 0, commands: [] }),
    );
    for (const [name, contents] of [
      ["flyctl", flyctl],
      ["docker", docker],
    ] as const) {
      const file = join(directory, name);
      writeFileSync(file, contents);
      chmodSync(file, 0o700);
    }
    const commit = "a".repeat(40);
    const digest = `sha256:${"b".repeat(64)}`;
    const args = [
      fileURLToPath(new URL("./deploy-server.ts", import.meta.url)),
      "staging",
      `ghcr.io/tnldotdev/tnl@${digest}`,
      `main-${commit}`,
      commit,
    ];
    const env = {
      ...process.env,
      PATH: `${directory}:${process.env.PATH ?? ""}`,
      TNLD_DATABASE_BRANCH: "staging",
      TNLD_DATABASE_DIRECT_URL: "postgres://user:secret@db.example.test/tnl",
      FAKE_COMMIT: commit,
      FAKE_DIGEST: digest,
      FAKE_FLY_STATE: stateFile,
    };
    const first = spawnSync(process.execPath, args, { env, encoding: "utf8" });
    expect(first.status, first.stderr).toBe(0);
    const initial = JSON.parse(readFileSync(stateFile, "utf8")) as {
      machines: Record<string, { id: string; state: string; image_ref: { digest: string } }[]>;
      commands: string[];
    };
    expect(initial.commands.filter((command) => command.startsWith("machine update"))).toEqual([
      "machine update tnl-relay-a-staging",
      "machine update tnl-relay-a-staging",
      "machine update tnl-relay-b-staging",
      "machine update tnl-relay-b-staging",
    ]);
    const ids = Object.values(initial.machines).flatMap((members) =>
      members.map((member) => member.id),
    );
    const firstRunCommands = initial.commands.length;
    const control = initial.machines["tnl-control-staging"]?.[0];
    if (!control) throw new Error("missing control fixture");
    control.state = "stopped";
    for (const members of Object.values(initial.machines)) {
      for (const member of members) member.image_ref.digest = `sha256:${"c".repeat(64)}`;
    }
    writeFileSync(stateFile, JSON.stringify(initial));
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = spawnSync(process.execPath, args, { env, encoding: "utf8" });
      expect(result.status, result.stderr).toBe(0);
      const intermediate = JSON.parse(readFileSync(stateFile, "utf8")) as { commands: string[] };
      expect(
        intermediate.commands.filter((command) => command.startsWith("machine update")),
      ).toHaveLength(12);
      if (attempt === 0) {
        const rollout = intermediate.commands.slice(firstRunCommands);
        expect(rollout.indexOf("machine update tnl-control-staging")).toBeLessThan(
          rollout.indexOf("machine start tnl-control-staging"),
        );
      }
    }
    const state = JSON.parse(readFileSync(stateFile, "utf8")) as {
      apps: string[];
      ips: Record<string, string[]>;
      machines: Record<
        string,
        {
          id: string;
          state: string;
          config: {
            env: Record<string, string>;
            metadata: { fly_process_group: string };
            services: { protocol: string; internal_port: number; ports: { port?: number }[] }[];
          };
        }[]
      >;
      commands: string[];
    };
    expect(state.apps).toHaveLength(4);
    for (const app of state.apps) expect(state.ips[app]).toEqual(["v4", "v6"]);
    expect(state.commands.filter((command) => command === "ips allocate-v4")).toHaveLength(4);
    expect(state.commands.filter((command) => command === "ips allocate-v6")).toHaveLength(4);
    expect(state.commands.filter((command) => command === "machine create")).toHaveLength(8);
    expect(state.commands.filter((command) => command.startsWith("machine update"))).toHaveLength(
      12,
    );
    expect(
      Object.values(state.machines).flatMap((members) => members.map((member) => member.id)),
    ).toEqual(ids);
    for (const role of ["relay-a", "relay-b"]) {
      const members = state.machines[`tnl-${role}-staging`];
      expect(members?.map((member) => member.config.metadata.fly_process_group).sort()).toEqual([
        "app",
        "udp",
      ]);
      expect(
        members?.filter((member) =>
          member.config.services.some((service) => service.protocol === "udp"),
        ),
      ).toHaveLength(1);
      expect(
        members?.every((member) => member.config.env.TNLD_INTERNAL_RELAY_ADDRESS?.includes(".vm.")),
      ).toBe(true);
    }
    expect(
      new Set(
        state.machines["tnl-ingress-staging"]?.map((member) => member.config.env.TNLD_INGRESS_ID),
      ).size,
    ).toBe(2);

    // a matching image digest alone must not leave an older ingress service on 443.
    const ingress = state.machines["tnl-ingress-staging"];
    if (!ingress) throw new Error("missing ingress fixture");
    const firstIngress = ingress[0];
    if (!firstIngress) throw new Error("missing ingress Machine");
    firstIngress.config.services[0] = {
      protocol: "tcp",
      internal_port: 8443,
      ports: [{ port: 443 }],
    };
    writeFileSync(stateFile, JSON.stringify(state));
    const [script, , reference] = args;
    if (!script || !reference) throw new Error("missing deployment fixture args");
    const manualArgs = [script, "staging", reference, `source-${commit}`, commit, "--existing"];
    const manualEnv = { ...env, FAKE_VERSION: "source" };
    const unavailable = state.machines["tnl-control-staging"]?.[0];
    if (!unavailable) throw new Error("missing control Machine");
    unavailable.state = "stopped";
    writeFileSync(stateFile, JSON.stringify(state));
    const rejected = spawnSync(process.execPath, manualArgs, { env: manualEnv, encoding: "utf8" });
    expect(rejected.status).toBe(1);
    expect(rejected.stderr).toContain("expected 2 started Machines");
    unavailable.state = "started";
    writeFileSync(stateFile, JSON.stringify(state));
    const manual = spawnSync(process.execPath, manualArgs, { env: manualEnv, encoding: "utf8" });
    expect(manual.status, manual.stderr).toBe(0);
    const restored = JSON.parse(readFileSync(stateFile, "utf8")) as typeof state;
    expect(restored.machines["tnl-ingress-staging"]?.[0]?.config.services[0]).toEqual(
      restored.machines["tnl-ingress-staging"]?.[1]?.config.services[0],
    );
    expect(manual.stdout).toContain("rollback tnl-ingress-staging");
    const portCheck = spawnSync(process.execPath, [script, "--check-staging-ingress"], {
      env: manualEnv,
      encoding: "utf8",
    });
    expect(portCheck.status, portCheck.stderr).toBe(0);
    expect(portCheck.stdout).toContain("2 Machines advertise the staged PROXY v2 ports");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
