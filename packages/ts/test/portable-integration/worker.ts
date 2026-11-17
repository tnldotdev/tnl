import { client, connect, deployment } from "@tnldotdev/tnl/cloudflare";
import { runPortableIsolation, runPortableSmoke } from "./smoke.ts";
import { PortableSmokeError, portableDiagnostics } from "./errors.ts";
import { fixtureSchema } from "./fixture.ts";
import { installFixtureHost } from "./host.ts";

const runtime = { client, connect, deployment };

interface Fetcher {
  fetch(request: Request): Promise<Response>;
}
interface Environment {
  CONTROL: Fetcher;
  RELAY0: Fetcher;
  RELAY1: Fetcher;
}
const nativeFetch = globalThis.fetch.bind(globalThis);
const hostRequests: string[] = [];

export default {
  async fetch(request: Request, environment: Environment): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") return new Response("ready");
    if (request.method === "GET" && url.pathname === "/platform") {
      const checks: Record<string, string> = {};
      for (const [name, options] of Object.entries({
        credentials: { credentials: "omit" },
        redirect: { redirect: "error" },
        body: { method: "POST", body: new Uint8Array([1]), signal: new AbortController().signal },
      } satisfies Record<string, RequestInit>)) {
        try {
          new Request("https://fixed-input.invalid/", options);
          checks[name] = "supported";
        } catch (error) {
          // all inputs above are fixed and contain no fixture data.
          checks[name] = error instanceof Error ? `${error.name}: ${error.message}` : "unsupported";
        }
      }
      return Response.json(checks);
    }
    if (request.method !== "POST") return new Response("POST required", { status: 405 });
    try {
      const fixture = fixtureSchema.parse(await request.json());
      installFixtureHost(fixture, async (input, init) => {
        const outgoing = new Request(input, init);
        const target = new URL(outgoing.url);
        try {
          const index = fixture.relays.findIndex((relay) => relay.address === target.host);
          const response = await (target.origin === fixture.control_url
            ? environment.CONTROL.fetch(outgoing)
            : index !== -1
              ? (index === 0 ? environment.RELAY0 : environment.RELAY1).fetch(outgoing)
              : nativeFetch(outgoing));
          hostRequests.push(`${outgoing.method} ${target.pathname}: ${response.status}`);
          if (hostRequests.length > 64) hostRequests.shift();
          return response;
        } catch {
          hostRequests.push(`${outgoing.method} ${target.pathname}: host fetch failed`);
          if (hostRequests.length > 64) hostRequests.shift();
          throw new Error("fixture host fetch failed");
        }
      });
      if (url.pathname === "/smoke") return Response.json(await runPortableSmoke(runtime, fixture));
      const role = url.searchParams.get("role");
      const run = url.searchParams.get("run");
      if (
        url.pathname === "/isolation" &&
        (role === "first" || role === "second") &&
        run !== null
      ) {
        return Response.json(await runPortableIsolation(runtime, fixture, role, run));
      }
      return new Response("unknown fixture operation", { status: 404 });
    } catch (error) {
      // fixture bodies contain credentials. do not include them or driver errors
      // in the HTTP reply; the runner reports the failing runtime/operation.
      const failures = error instanceof AggregateError ? error.errors : [error];
      const phases = failures.flatMap((failure: unknown) =>
        failure instanceof PortableSmokeError
          ? [{ phase: failure.phase, code: failure.code, detail: failure.detail }]
          : [],
      );
      return Response.json(
        {
          error: "portable SDK integration failed",
          failures: phases,
          network: [...hostRequests],
          diagnostics: portableDiagnostics(),
        },
        { status: 500 },
      );
    }
  },
};
