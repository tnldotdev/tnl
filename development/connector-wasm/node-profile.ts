import { mkdir, writeFile } from "node:fs/promises";
import type { Profiler } from "node:inspector";
import path from "node:path";
import type { ConnectorBridge } from "./abi.ts";
import { observeBridge } from "./diagnostics.ts";
import type { WarmDiagnostics } from "./diagnostics.ts";
import type { ObserveWarm } from "./postgres.ts";

const frameCategories: ReadonlyArray<readonly [RegExp, string]> = [
  [
    /crypto_internal|crypto\/internal|x_crypto|crypto[._/](?:sha|aes|cipher)/,
    "crypto-primitive-stack",
  ],
  [/runtime[._/](?:gc|malloc|scan|mark|sweep|newobject|makeslice)/, "go-allocation-gc-stack"],
  [
    /syscall[._/]js|watch(?:Compact)?Promise|main[._/]promise|valueCall|copyBytes|loadString|storeValue|wasm-to-js/,
    "bridge-runtime-stack",
  ],
  [/runtime[._/](?:selectgo|schedule|findRunnable|gogo|gopark)/, "go-scheduler-stack"],
];

function category(stack: string[]): string {
  if (stack[0] === "(idle)") return "idle";
  if (stack[0] === "(garbage collector)") return "v8-gc";
  if (
    stack.some((frame) =>
      /runtime[._/](?:SetFinalizer|addspecial)|syscall[._/]js[._/](?:makeValue|finalizeRef)/.test(
        frame,
      ),
    )
  )
    return "js-value-bookkeeping";
  // prefer the work nearest the leaf: a syscall made beneath TLS is bridge
  // bookkeeping, not cipher arithmetic merely because TLS is on its stack.
  for (const frame of stack)
    for (const [pattern, name] of frameCategories) if (pattern.test(frame)) return name;
  return "other";
}

// sampled time is not wall-clock attribution: waiting and background runtime work
// can appear too. retain raw profiles so the heuristic categories can be audited.
export function summarizeProfile(
  profile: Profiler.Profile,
): Omit<NonNullable<WarmDiagnostics["cpuProfile"]>, "file" | "scope"> {
  const nodes = new Map(profile.nodes.map((node) => [node.id, node]));
  const parents = new Map<number, number>();
  for (const node of profile.nodes)
    for (const child of node.children ?? []) parents.set(child, node.id);
  const totals = new Map<string, number>();
  const categories: Record<string, number> = {};
  let sampledUs = 0;
  for (const [index, id] of (profile.samples ?? []).entries()) {
    const name = nodes.get(id)?.callFrame.functionName ?? "unknown";
    const micros = profile.timeDeltas?.[index] ?? 0;
    sampledUs += micros;
    totals.set(name, (totals.get(name) ?? 0) + micros);
    const stack: string[] = [];
    for (
      let current: number | undefined = id;
      current !== undefined;
      current = parents.get(current)
    )
      stack.push(nodes.get(current)?.callFrame.functionName ?? "unknown");
    const bucket = category(stack);
    categories[bucket] = (categories[bucket] ?? 0) + micros / 1000;
  }
  return {
    sampledMs: sampledUs / 1000,
    categoriesMs: categories,
    top: [...totals]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 25)
      .map(([name, micros]) => ({ function: name, selfMs: micros / 1000 })),
  };
}

export function observeQueries(bridge: ConnectorBridge, profileFile?: string): ObserveWarm {
  return async (label, sample) => {
    // these counters and ciphers belong to WASM, never to the native connector.
    if (label === "native") return sample();
    const session =
      label === "wasm" && profileFile
        ? new (await import("node:inspector/promises")).Session()
        : undefined;
    if (session) {
      session.connect();
      await session.post("Profiler.enable");
      await session.post("Profiler.setSamplingInterval", { interval: 100 });
    }
    try {
      let profile: Profiler.Profile | undefined;
      const measured = await observeBridge(bridge, async () => {
        await session?.post("Profiler.start");
        try {
          return await sample();
        } finally {
          if (session) profile = (await session.post("Profiler.stop")).profile;
        }
      });
      if (profile && profileFile) {
        await mkdir(path.dirname(profileFile), { recursive: true });
        await writeFile(profileFile, JSON.stringify(profile), { mode: 0o600 });
        measured.diagnostics.cpuProfile = {
          file: profileFile,
          scope: "query-call-and-profiler-control-not-exact-loop-decomposition",
          ...summarizeProfile(profile),
        };
      }
      return measured;
    } finally {
      session?.disconnect();
    }
  };
}
