import * as z from "zod";
import { hostDetailsSchema, hostOrigin, hostSchema, runIDSchema, type Change } from "./gossip.ts";
import { readJSON } from "../release.ts";

const visibleHost = hostSchema.refine(({ origin }) => hostOrigin(origin));
export const MAX_FALLBACK_HOSTS = 3;
export const MAX_TREE_HOSTS = 64;
export const TREE_PATH = "/__keepalive/tree";
export const presenceSummary = z.strictObject({
  host: visibleHost,
  startedAt: z.int().nonnegative(),
  tabs: z.int().nonnegative(),
  hosts: z.int().positive(),
  fallback: z.array(visibleHost).max(MAX_FALLBACK_HOSTS),
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
  });
const treeView = z.strictObject({
  hostRunID: runIDSchema,
  hosts: z.array(treeHost).max(MAX_TREE_HOSTS),
});

export function treeSample(roster: readonly Change[], focus: string) {
  const runs = new Map(roster.map((host) => [host.runID, host]));
  const selected = new Set<Change>();
  // keep the branch around the counting host even when the roster is large.
  for (let id: string | undefined = focus; id !== undefined && selected.size < MAX_TREE_HOSTS;) {
    const host = runs.get(id);
    if (host === undefined || selected.has(host)) break;
    selected.add(host);
    id = host.copyFrom;
  }
  for (const host of roster) {
    if (selected.size >= MAX_TREE_HOSTS) break;
    selected.add(host);
  }
  return [...selected].map(({ runID, name, endsAt, copyFrom, left }) => ({
    runID,
    name,
    endsAt,
    copyFrom,
    left,
  }));
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
  const view = treeView.safeParse(await readJSON(response, 16_384, deadline));
  return view.success && view.data.hostRunID === hostRunID ? view.data.hosts : undefined;
}
