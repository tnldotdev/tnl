import {
  createDurableObjectPublisher,
  type DurableObjectPublisherState,
} from "@tnldotdev/tnl/durable-object";
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

// this is an actual SQLite-backed workerd durable object, not the injected
// deployment/storage doubles used by portable/durable-object.test.ts.
export class Publisher {
  readonly #owner: ReturnType<typeof createDurableObjectPublisher>;
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
    this.#owner = createDurableObjectPublisher(state, {
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

export default {
  async fetch(request: Request, environment: Environment): Promise<Response> {
    return environment.PUBLISHERS.get(environment.PUBLISHERS.idFromName("publisher")).fetch(
      request,
    );
  },
};
