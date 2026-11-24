import * as z from "zod";
import {
  audienceSchema,
  hostDetailsSchema,
  hostOrigin,
  hostSchema,
  releaseIDSchema,
  runIDSchema,
  type HostHistory,
} from "./gossip.ts";
import { readJSON } from "../release.ts";

const visibleHost = hostSchema.refine(({ origin }) => hostOrigin(origin));
export const MAX_FALLBACK_HOSTS = 3;
export const MAX_TREE_HOSTS = 96;
export const TREE_PATH = "/__keepalive/tree";
export const presenceSummary = z.strictObject({
  host: visibleHost,
  startedAt: z.int().nonnegative(),
  tabs: z.int().nonnegative(),
  hosts: z.int().positive(),
  saturated: z.boolean(),
  sampling: z.boolean().optional(),
  fallback: z.array(visibleHost).max(MAX_FALLBACK_HOSTS),
});
export const audienceSnapshot = audienceSchema.extend({
  releaseID: releaseIDSchema,
  host: visibleHost,
  startedAt: z.int().nonnegative(),
});
export const treeHost = hostDetailsSchema
  .pick({
    name: true,
    endsAt: true,
    copyFrom: true,
  })
  .extend({
    runID: runIDSchema,
    left: z.boolean(),
    unreachable: z.boolean().optional(),
  });
const treeView = z.strictObject({
  hostRunID: runIDSchema,
  hosts: z.array(treeHost).max(MAX_TREE_HOSTS),
});

export function treeSample(roster: readonly HostHistory[], focus: string) {
  const runs = new Map<string, HostHistory>();
  const children = new Map<string, string[]>();
  for (const host of roster) {
    if (runs.has(host.runID)) continue;
    runs.set(host.runID, host);
    if (host.copyFrom !== undefined) {
      const group = children.get(host.copyFrom) ?? [];
      group.push(host.runID);
      children.set(host.copyFrom, group);
    }
  }
  const selected = new Map<string, HostHistory>();
  const add = (id: string) => {
    const host = runs.get(id);
    if (host === undefined || selected.has(id)) return false;
    selected.set(id, host);
    return true;
  };
  // share the response budget between the path to this host and the tabs it seeded.
  add(focus);
  let ancestor = runs.get(focus)?.copyFrom;
  const descendants = [...(children.get(focus) ?? [])];
  for (
    let i = 0;
    selected.size < MAX_TREE_HOSTS && (ancestor !== undefined || i < descendants.length);
    i++
  ) {
    if (ancestor !== undefined) ancestor = add(ancestor) ? runs.get(ancestor)?.copyFrom : undefined;
    const child = descendants[i];
    if (child !== undefined && selected.size < MAX_TREE_HOSTS && add(child))
      descendants.push(...(children.get(child) ?? []));
  }
  for (const host of roster) {
    if (selected.size >= MAX_TREE_HOSTS) break;
    add(host.runID);
  }
  return [...selected.values()];
}

export async function readTree(origin: string, hostRunID: string, signal: AbortSignal) {
  if (!hostOrigin(origin)) return;
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(4_000)]);
  const response = await fetch(new URL(TREE_PATH, origin), {
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
    signal: deadline,
  });
  const view = treeView.safeParse(await readJSON(response, 32_768, deadline));
  return view.success && view.data.hostRunID === hostRunID ? view.data.hosts : undefined;
}
