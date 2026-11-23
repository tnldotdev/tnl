import {
  connect,
  deployment,
  publish,
  publisher,
  TnlPublisher as PublisherObject,
} from "@tnldotdev/tnl/cloudflare";
import {
  durablePublisher,
  type DurableObjectPublisherState,
} from "../../dist/durable-object.worker.js";
import { check, durablePublisherFailure, fixtureSchema, publisherFailures } from "./fixture.ts";
import { publisherHandler } from "./handler.ts";
import { installPublisherFixtureHost, runtimeStarts } from "./host.ts";

interface Fetcher {
  fetch(request: Request): Promise<Response>;
}
interface ControlObservation {
  operation: "run.close" | "audit.report";
  status: number | "pending" | "rejected";
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
  PRIVATE_PUBLISHERS: Environment["PUBLISHERS"];
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
  readonly #url: string | undefined;
  readonly #exitKey: string;
  readonly #control: ControlObservation[] = [];
  #identityImports = 0;

  constructor(state: DurableObjectPublisherState, environment: Environment, service = "web") {
    const fixture = fixtureSchema.parse(JSON.parse(environment.FIXTURE));
    this.#url = service === "web" ? fixture.named_url : undefined;
    this.#exitKey =
      this.#url === undefined ? "__tnlWasmPrivatePublisherExit" : "__tnlWasmPublicPublisherExit";
    Reflect.deleteProperty(globalThis, this.#exitKey);
    prepareFixtureHost(fixture, environment, this.#control);
    this.#owner = durablePublisher(state, {
      configuration: { project: fixture.project, deployment: fixture.deployment, service },
      identity: () => {
        this.#identityImports++;
        return new TextEncoder().encode(fixture.token);
      },
      handler: () => publisherHandler(this.#runtime).handle,
    });
  }

  async fetch(request: Request): Promise<Response> {
    let phase: "ready" | "start" | "stop" | "resume" = "ready";
    try {
      await this.#owner.ready;
      const operation = new URL(request.url).pathname;
      if (operation === "/start") {
        phase = "start";
        const publication = await this.#owner.start();
        check(publication.url === this.#url, "named durable publication changed URL");
        if (this.#url === undefined)
          check(!("url" in publication), "private durable publication exposed a public URL");
      } else if (operation === "/stop") {
        phase = "stop";
        await this.#owner.stop();
      } else if (operation === "/resume" || operation === "/status") {
        phase = "resume";
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
    } catch (error) {
      const exit: unknown = Reflect.get(globalThis, this.#exitKey);
      return Response.json(
        { control: this.#control, ...durablePublisherFailure(error, phase, exit) },
        { status: 500 },
      );
    }
  }

  async alarm(): Promise<void> {
    await this.#owner.alarm();
  }
}

export class PrivatePublisher extends Publisher {
  constructor(state: DurableObjectPublisherState, environment: Environment) {
    super(state, environment, "private");
  }
}

function prepareFixtureHost(
  fixture: ReturnType<typeof fixtureSchema.parse>,
  environment: Environment,
  control?: ControlObservation[],
): void {
  installPublisherFixtureHost(fixture);
  Reflect.set(globalThis, "fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (url.origin === fixture.control_url) {
      const op =
        request.method === "DELETE" && /^\/v1\/services\/[^/]+\/runs\/[^/]+$/.test(url.pathname)
          ? "run.close"
          : url.pathname.endsWith("/service-observations")
            ? "audit.report"
            : undefined;
      const entry: ControlObservation | undefined =
        op === undefined ? undefined : { operation: op, status: "pending" };
      if (entry !== undefined && control !== undefined) {
        if (control.length === 8) control.shift();
        control.push(entry);
      }
      let response: Response;
      try {
        response = await environment.CONTROL.fetch(request);
      } catch (error) {
        if (entry !== undefined) entry.status = "rejected";
        throw error;
      }
      if (entry !== undefined) entry.status = response.status;
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
    if (route.pathname === "/managed-target") return new Response("private managed publisher");
    if (route.pathname.startsWith("/managed-")) {
      const fixture = fixtureSchema.parse(JSON.parse(environment.FIXTURE));
      prepareFixtureHost(fixture, environment);
      let phase = "open";
      try {
        if (route.pathname === "/managed-stop") {
          const owner = await publisher(ctx);
          await (await publish(owner, "private")).close();
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
          const managed = await publish(owner, "private");
          check(!("url" in managed), "managed private publication returned a public URL");
          const exported = await managed.exportCertificate();
          check(
            exported.expiresAt > Date.now() &&
              exported.certificate.certificatePEM.startsWith("-----BEGIN CERTIFICATE-----") &&
              exported.certificate.privateKeyPEM.startsWith("-----BEGIN PRIVATE KEY-----"),
            "managed private publication did not export its installed certificate and key",
          );
          return Response.json({ publisher: owner.publisherIdentityID, calls });
        }
      } catch (error) {
        return Response.json(publisherFailures(error, phase), { status: 500 });
      }
    }
    if (route.pathname === "/private-visit" || route.pathname === "/managed-visit") {
      const fixture = fixtureSchema.parse(JSON.parse(environment.FIXTURE));
      prepareFixtureHost(fixture, environment);
      const owner = deployment(fixture.deployment, {
        project: fixture.project,
        token: fixture.token,
        services: { private: { protocol: "http" } },
      });
      try {
        const connection = await connect(owner, "private");
        const managedVisit = route.pathname === "/managed-visit";
        const response = await connection.fetch(managedVisit ? "/managed-target" : "/probe");
        if (
          response.ok &&
          (await response.text()) ===
            (managedVisit ? "private managed publisher" : "portable-publisher")
        )
          return Response.json({ private: true });
        return Response.json({ error: "private target did not respond" }, { status: 502 });
      } finally {
        await owner.close();
      }
    }
    if (route.pathname === "/private-start" || route.pathname === "/private-stop") {
      route.pathname = route.pathname === "/private-start" ? "/start" : "/stop";
      const namespace = environment.PRIVATE_PUBLISHERS;
      return namespace.get(namespace.idFromName("private")).fetch(new Request(route, request));
    }
    return environment.PUBLISHERS.get(environment.PUBLISHERS.idFromName("publisher")).fetch(
      request,
    );
  },
};
