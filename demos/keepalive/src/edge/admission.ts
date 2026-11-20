import * as z from "zod";
import { BOOTSTRAP_TURN_MS, HOST_TURN_MS, MAX_HOSTS, MAX_STARTING, STARTUP_MS } from "../policy.ts";
import { readJSON } from "../release.ts";

export type CoordinatorBinding = {
  getByName(name: string): { fetch(request: Request): Promise<Response> };
};
type Storage = {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown): Promise<void>;
};
type State = {
  storage: Storage & { transaction<T>(work: (storage: Storage) => Promise<T>): Promise<T> };
};
export const admissionOperation = z.discriminatedUnion("state", [
  z.strictObject({ state: z.literal("reserve"), requestID: z.uuid(), bootstrap: z.boolean() }),
  z.strictObject({ state: z.enum(["ready", "stop"]), requestID: z.uuid() }),
]);
// compact tuples keep the bounded inventory below the storage value limit.
const reservation = z
  .tuple([z.uuid(), z.int(), z.int(), z.boolean()])
  .transform(([requestID, startingUntil, expiresAt, ready]) => ({
    requestID,
    startingUntil,
    expiresAt,
    ready,
  }));
const reservations = z.array(reservation).max(MAX_HOSTS + MAX_STARTING);

// one object owns admission, not site bytes or request forwarding. transactions
// prevent simultaneous Worker isolates from oversubscribing startup capacity.
export class AdmissionCoordinator {
  private readonly state: State;

  constructor(state: State) {
    this.state = state;
  }

  async fetch(request: Request) {
    const parsed = admissionOperation.safeParse(
      await readJSON(new Response(request.body), 1_024, request.signal).catch(() => undefined),
    );
    if (request.method !== "POST" || !parsed.success) return new Response(null, { status: 400 });
    const value = parsed.data;
    return this.state.storage.transaction(async (storage) => {
      const now = Date.now();
      const saved = await storage.get("reservations");
      const entries = reservations
        .parse(saved ?? [])
        .filter((entry) => entry.expiresAt > now && (entry.ready || entry.startingUntil > now));
      const current = entries.find((entry) => entry.requestID === value.requestID);
      let status = 204;
      if (value.state === "reserve") {
        if (current === undefined) {
          if (
            entries.length >= MAX_HOSTS + MAX_STARTING ||
            entries.filter((entry) => !entry.ready).length >= MAX_STARTING
          ) {
            status = 429;
          } else {
            entries.push({
              requestID: value.requestID,
              startingUntil: now + STARTUP_MS,
              expiresAt: now + STARTUP_MS + (value.bootstrap ? BOOTSTRAP_TURN_MS : HOST_TURN_MS),
              ready: false,
            });
          }
        }
      } else if (value.state === "ready") {
        if (current === undefined) status = 409;
        else current.ready = true;
      } else if (current !== undefined) {
        entries.splice(entries.indexOf(current), 1);
      }
      await storage.put(
        "reservations",
        entries.map(({ requestID, startingUntil, expiresAt, ready }) => [
          requestID,
          startingUntil,
          expiresAt,
          ready,
        ]),
      );
      return new Response(null, {
        status,
        headers: {
          "Cache-Control": "no-store",
          ...(status === 429 ? { "Retry-After": "10" } : {}),
        },
      });
    });
  }
}

export function admissionRequest(
  coordinator: CoordinatorBinding,
  body: z.infer<typeof admissionOperation>,
  signal: AbortSignal,
) {
  return coordinator.getByName("canwe").fetch(
    new Request("https://admission.internal/", {
      method: "POST",
      body: JSON.stringify(body),
      signal,
    }),
  );
}
