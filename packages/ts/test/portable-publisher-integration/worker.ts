import {
  publish,
  publisher,
  TnlPublisher as PublisherObject,
} from "@tnldotdev/tnl/cloudflare";
import {
  durablePublisher,
  type DurableObjectPublisherState,
} from "../../dist/durable-object.worker.js";
import { check, fixtureSchema } from "./fixture.ts";
import { publisherHandler } from "./handler.ts";
import { installPublisherFixtureHost, runtimeStarts } from "./host.ts";

interface Fetcher {
  fetch(request: Request): Promise<Response>;
}
interface Environment {
  FIXTURE: string;
  CONTROL: Fetcher;
  RELAY0: Fetcher;
  RELAY1: Fetcher;
  PUBLISHERS: {
    idFromName(name: string): unknown;
    get(id: unknown): Fetcher;
  };
}
const nativeFetch = globalThis.fetch.bind(globalThis);

// the fixture uses private roots and local relay bindings; production directly
// re-exports the SDK class and uses the platform's normal fetch.
export class TnlPublisher extends PublisherObject {
  constructor(state: DurableObjectPublisherState & { exports: unknown }, env: Environment) {
    prepareFixtureHost(fixtureSchema.parse(JSON.parse(env.FIXTURE)), env);
    super(state, env);
  }
}

// this is an actual SQLite-backed workerd durable object, not the injected
// deployment/storage doubles used by portable/durable-object.test.ts.
export class Publisher {
  readonly #owner: ReturnType<typeof durablePublisher>;
  readonly #runtime = crypto.randomUUID();
  readonly #url: string;
  #identityImports = 0;

  constructor(state: DurableObjectPublisherState, environment: Environment) {
    const fixture = fixtureSchema.parse(JSON.parse(environment.FIXTURE));
    this.#url = fixture.named_url;
    installPublisherFixtureHost(fixture);
    Reflect.set(globalThis, "fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.origin === fixture.control_url) return environment.CONTROL.fetch(request);
      const index = fixture.relays.findIndex((relay) => relay.address === url.host);
      if (index !== -1)
        return (index === 0 ? environment.RELAY0 : environment.RELAY1).fetch(request);
      return nativeFetch(request);
    });
    this.#owner = durablePublisher(state, {
      configuration: { project: fixture.project, deployment: fixture.deployment, service: "web" },
      identity: () => {
        this.#identityImports++;
        return new TextEncoder().encode(fixture.token);
      },
      handler: () => publisherHandler(this.#runtime).handle,
    });
  }

  async fetch(request: Request): Promise<Response> {
    try {
      await this.#owner.ready;
      const operation = new URL(request.url).pathname;
      if (operation === "/start") {
        const publication = await this.#owner.start();
        check(publication.url === this.#url, "named durable publication changed URL");
      } else if (operation === "/stop") {
        await this.#owner.stop();
      } else if (operation === "/resume" || operation === "/status") {
        await this.#owner.resume();
      } else {
        return new Response("unknown fixture operation", { status: 404 });
      }
      return Response.json({
        url: this.#url,
        runtime: this.#runtime,
        go_runtimes: runtimeStarts(),
        identity_imports: this.#identityImports,
      });
    } catch {
      // do not return request data, signing credentials or arbitrary go errors.
      return Response.json({ error: "actual Go/WASM durable publisher failed" }, { status: 500 });
    }
  }

  async alarm(): Promise<void> {
    await this.#owner.alarm();
  }
}

function prepareFixtureHost(
  fixture: ReturnType<typeof fixtureSchema.parse>,
  environment: Environment,
): void {
  installPublisherFixtureHost(fixture);
  Reflect.set(globalThis, "fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (url.origin === fixture.control_url) {
      const response = await environment.CONTROL.fetch(request);
      if (
        url.pathname === "/v1/publisher/deployments/enroll" ||
        url.pathname === "/v1/publisher/deployments/verify"
      )
        console.error("publisher fixture enrollment response", url.pathname, response.status);
      return response;
    }
    const index = fixture.relays.findIndex((relay) => relay.address === url.host);
    if (index !== -1) return (index === 0 ? environment.RELAY0 : environment.RELAY1).fetch(request);
    return nativeFetch(request);
  });
}

export default {
  async fetch(
    request: Request,
    environment: Environment,
    ctx: { exports: unknown },
  ): Promise<Response> {
    const route = new URL(request.url);
    if (route.pathname === "/probe")
      return new Response("managed publisher", { headers: { "X-Publisher-Runtime": "managed" } });
    if (route.pathname.startsWith("/managed-")) {
      const fixture = fixtureSchema.parse(JSON.parse(environment.FIXTURE));
      prepareFixtureHost(fixture, environment);
      let phase = "open";
      try {
        if (route.pathname === "/managed-stop") {
          const owner = await publisher(ctx);
          await (await publish(owner, "web")).close();
          return Response.json({ stopped: true });
        }
        if (route.pathname === "/managed-start" || route.pathname === "/managed-reopen") {
          let calls = 0;
          const enrollment = () => {
            calls++;
            if (route.pathname === "/managed-reopen") throw new Error("saved identity was ignored");
            return fixture.enrollment;
          };
          const owner = await publisher(ctx, {
            ...(route.pathname === "/managed-start" ? { controlUrl: fixture.control_url } : {}),
            enrollment,
          });
          phase = "publish";
          const managed = await publish(owner, "web");
          check(managed.url === fixture.named_url, "managed publication changed the service URL");
          return Response.json({ publisher: owner.publisherIdentityID, calls });
        }
      } catch (error) {
        return Response.json(
          { phase, kind: error instanceof Error ? error.name : "failure" },
          { status: 500 },
        );
      }
    }
    return environment.PUBLISHERS.get(environment.PUBLISHERS.idFromName("publisher")).fetch(
      request,
    );
  },
};
