import * as z from "zod/mini";
import { fleet } from "../fleets.ts";

export const HOST_PARENT: string = fleet.parent;
export const SHARED_HOST = `https://site.${HOST_PARENT}`;
export const PEERS_PATH = "/__keepalive/peers";
export const releaseIDSchema = z.string().check(z.regex(/^[a-f0-9]{64}$/));
export const runIDSchema = z.string().check(z.regex(/^srun_[A-Za-z0-9]{22}$/));
export const httpsOriginSchema = z.string().check(
  z.maxLength(261),
  z.refine((value) => {
    const url = URL.parse(value);
    return url?.protocol === "https:" && url.origin === value;
  }),
);
export const hostSchema = z.object({
  origin: httpsOriginSchema,
  publisherID: z.string().check(z.regex(/^pub_[A-Za-z0-9]{22}$/)),
  runID: runIDSchema,
  runNumber: z.string().check(
    z.regex(/^[1-9]\d{0,18}$/),
    z.refine((value) => value.length < 19 || value <= "9223372036854775807"),
  ),
});
export type Host = Readonly<z.infer<typeof hostSchema>>;

export function hostOrigin(value: unknown, parent = HOST_PARENT): value is string {
  if (typeof value !== "string" || value.length > 261) return false;
  const url = URL.parse(value);
  if (url?.protocol !== "https:" || url.origin !== value || url.port !== "") return false;
  if (!url.hostname.endsWith(`.${parent}`)) return false;
  return /^p-[a-z2-7]{26}$/.test(url.hostname.slice(0, -(parent.length + 1)));
}

export function parseHost(value: unknown, parent = HOST_PARENT): Host | undefined {
  const parsed = hostSchema.safeParse(value);
  if (parsed.success && hostOrigin(parsed.data.origin, parent)) return parsed.data;
  return undefined;
}

export function sameRun(a: Host, b: Host): boolean {
  return (
    a.publisherID === b.publisherID &&
    a.origin === b.origin &&
    a.runID === b.runID &&
    a.runNumber === b.runNumber
  );
}

export function hostIdentity({ origin, publisherID, runID, runNumber }: Host): Host {
  return { origin, publisherID, runID, runNumber };
}
