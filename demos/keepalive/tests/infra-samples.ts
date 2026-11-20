import { readFile } from "node:fs/promises";
import * as z from "zod";
import { readJSON } from "../src/release.ts";
import { periodic, type RecordSample } from "./measure.ts";

// each query must select one aggregate for the test deployment, or one relay.
// never copy backend labels, URLs, credentials, or error bodies to the report.
const settings = z.strictObject({
  endpoint: z.url({ protocol: /^https?$/ }),
  queries: z
    .record(z.string().regex(/^[a-z][a-z0-9_]{0,63}$/), z.string().min(1).max(2048))
    .refine((q) => Object.keys(q).length > 0 && Object.keys(q).length <= 32),
});
const instant = z.object({
  status: z.literal("success"),
  data: z.object({
    resultType: z.literal("vector"),
    result: z.array(z.object({ value: z.tuple([z.number(), z.string()]) })).length(1),
  }),
});

export async function observeInfrastructure(file: string, emit: RecordSample) {
  const config = settings.parse(JSON.parse(await readFile(file, "utf8")));
  const endpoint = new URL(config.endpoint);
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash)
    throw new Error("supply a query endpoint without embedded credentials");
  if (
    endpoint.protocol !== "https:" &&
    !["localhost", "127.0.0.1", "[::1]"].includes(endpoint.hostname)
  )
    throw new Error("use HTTPS for remote metrics");
  const token = process.env.KEEPALIVE_METRICS_TOKEN;
  return periodic(
    15_000,
    async (parent) => {
      await Promise.all(
        Object.entries(config.queries).map(async ([name, query]) => {
          const url = new URL(endpoint);
          url.searchParams.set("query", query);
          const signal = AbortSignal.any([parent, AbortSignal.timeout(5_000)]);
          try {
            const response = await fetch(url, {
              signal,
              redirect: "error",
              headers: token ? { Authorization: `Bearer ${token}` } : {},
            });
            const result = instant.parse(await readJSON(response, 64 * 1024, signal)).data
              .result[0];
            const raw = result?.value[1].trim();
            const value = Number(raw);
            if (!result || !raw || !Number.isFinite(value)) throw new Error("missing sample");
            emit("infrastructure", { name, value, sourceAtMs: result.value[0] * 1000 });
          } catch {
            if (!parent.aborted) emit("infrastructure", { name, value: null });
          }
        }),
      );
    },
    (slots) => emit("infra_skipped", { slots }),
  );
}
