import { DurableObject } from "cloudflare:workers";
import * as z from "zod";
import module from "../../wasm/publisher.wasm";
import { TnlError } from "../../errors.js";
import type { DurableObjectPublisherState } from "../../durable-object.js";
import type { FetchHandler } from "../publisher/fetch_types.js";
import type { Publication } from "../publisher/publication.js";
import { httpsOriginSchema, serviceNameSchema } from "../values.js";
import { loadWasm } from "../connector/wasm_loader.js";
import {
  workerTarget,
  type WorkerPublicationData,
  type WorkerPublicationTarget,
} from "./cloudflare-publisher-client.js";
import { enrollPortablePublisher, type EnrolledPublisher } from "./enrollment.js";
import { createDurableObjectPublisherStorage } from "./storage-durable-object.js";
import { PublisherStorageError, type PublisherStorage } from "./storage.js";

interface PublisherState extends DurableObjectPublisherState {
  readonly exports: unknown;
}

const intentKey = "managed-intent-v1";
const alarmInterval = 60_000;
const maximumServices = 32;
const intentSchema = z.strictObject({
  version: z.literal(1),
  services: z
    .array(z.strictObject({ service: serviceNameSchema, id: z.uuid(), target: workerTarget }))
    .max(maximumServices)
    .refine((values) => new Set(values.map((v) => v.service)).size === values.length),
});
type Intent = z.output<typeof intentSchema>["services"][number];
interface Running {
  readonly intent: Intent;
  readonly publication: Publication;
}

// the worker's loopback RPC sends only target names. the durable object owns
// the identity, intent and wasm lifetime; go owns each authorized service run.
export class TnlPublisher extends DurableObject {
  readonly #state: PublisherState;
  readonly #env: unknown;
  readonly #storage: PublisherStorage;
  #identity: EnrolledPublisher | undefined;
  #queue: Promise<void> = Promise.resolve();
  #intent: Map<string, Intent> | undefined;
  readonly #running = new Map<string, Running>();

  constructor(state: PublisherState, env: unknown) {
    super(state, env);
    this.#state = state;
    this.#env = env;
    this.#storage = createDurableObjectPublisherStorage(state.storage, "managed");
  }

  open(controlUrl?: string, enrollment?: () => Promise<string>) {
    return this.#serialize(async () => {
      if (controlUrl !== undefined && !httpsOriginSchema.safeParse(controlUrl).success)
        throw new TnlError("sdk.configuration_invalid");
      if (enrollment !== undefined && typeof enrollment !== "function")
        throw new TnlError("sdk.configuration_invalid");
      const identity = await this.#open(controlUrl, enrollment);
      return {
        publisherIdentityID: identity.publisherIdentityID,
        deploymentID: identity.deploymentID,
      };
    });
  }

  start(service: string, target: WorkerPublicationTarget): Promise<WorkerPublicationData> {
    return this.#serialize(async () => {
      const selected = workerTarget.safeParse(target);
      if (!selected.success || !serviceNameSchema.safeParse(service).success)
        throw new TnlError("sdk.configuration_invalid");
      this.#target(selected.data);
      const identity = await this.#open();
      const intents = await this.#intents();
      const current = intents.get(service);
      if (current === undefined && intents.size >= maximumServices)
        throw new TnlError("sdk.client_capacity");
      const intent =
        current !== undefined && JSON.stringify(current.target) === JSON.stringify(selected.data)
          ? current
          : { service, target: selected.data, id: crypto.randomUUID() };

      // arm before committing intent so a restart after the write can recover.
      await this.#arm();
      if (intent !== current) await this.#save(new Map(intents).set(service, intent));
      return this.#result(await this.#start(identity, intent));
    });
  }

  stop(service: string, id: string): Promise<void> {
    return this.#serialize(async () => {
      if (!serviceNameSchema.safeParse(service).success || !z.uuid().safeParse(id).success)
        throw new TnlError("sdk.configuration_invalid");
      const intents = await this.#intents();
      const current = intents.get(service);
      if (current !== undefined && current.id !== id) return;
      if (current !== undefined) {
        const next = new Map(intents);
        next.delete(service);
        await this.#save(next);
      }
      const running = this.#running.get(service);
      if (running?.intent.id === id) await this.#closeRun(running);
      if ((await this.#intents()).size === 0 && this.#running.size === 0) {
        if (this.#identity !== undefined) {
          await this.#identity.close();
          this.#identity = undefined;
        }
        await this.#state.storage.deleteAlarm();
      }
    });
  }

  alarm(): Promise<void> {
    return this.#serialize(async () => {
      const intents = await this.#intents();
      if (intents.size === 0) return;
      await this.#arm();
      const identity = await this.#open();
      const results = await Promise.allSettled(
        [...intents.values()].map((intent) => this.#start(identity, intent)),
      );
      if (results.some((result) => result.status === "rejected"))
        throw new TnlError("sdk.publication_failed");
    });
  }

  #serialize<T>(operation: () => Promise<T>): Promise<T> {
    const running = this.#queue.then(operation);
    this.#queue = running.then(
      () => {},
      () => {},
    );
    this.#state.waitUntil(this.#queue);
    return running;
  }

  async #open(controlUrl?: string, enrollment?: () => Promise<string>): Promise<EnrolledPublisher> {
    if (this.#identity === undefined) {
      this.#identity = await enrollPortablePublisher(
        {
          publisherStorage: this.#storage,
          ...(controlUrl === undefined ? {} : { controlUrl }),
          // abort signals are local to an event and are not RPC arguments.
          ...(enrollment === undefined ? {} : { enrollment: () => enrollment() }),
        },
        () => loadWasm(module),
      );
    }
    if (controlUrl !== undefined && controlUrl !== this.#identity.controlUrl)
      throw new TnlError("sdk.configuration_invalid");
    return this.#identity;
  }

  async #intents(): Promise<Map<string, Intent>> {
    if (this.#intent === undefined) {
      const raw = await this.#storage.get(intentKey);
      if (raw === undefined) this.#intent = new Map();
      else {
        try {
          const parsed = intentSchema.parse(
            JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)),
          );
          this.#intent = new Map(parsed.services.map((intent) => [intent.service, intent]));
        } catch {
          throw new PublisherStorageError("sdk.publisher_storage_invalid");
        }
      }
    }
    return this.#intent;
  }

  async #save(next: Map<string, Intent>): Promise<void> {
    try {
      await this.#storage.put(
        intentKey,
        new TextEncoder().encode(JSON.stringify({ version: 1, services: [...next.values()] })),
      );
      await this.#storage.sync(intentKey);
      this.#intent = next;
    } catch (error) {
      // a storage failure may have happened after the write committed.
      this.#intent = undefined;
      throw error;
    }
  }

  #arm(): Promise<void> {
    return this.#state.storage.setAlarm(Date.now() + alarmInterval);
  }

  #target(target: WorkerPublicationTarget): FetchHandler {
    const bindings = "binding" in target ? this.#env : this.#state.exports;
    const name =
      "binding" in target ? target.binding : "entrypoint" in target ? target.entrypoint : "default";
    if (typeof bindings !== "object" || bindings === null || name === "TnlPublisher")
      throw new TnlError("sdk.configuration_invalid");
    const binding: unknown = Reflect.get(bindings, name);
    if (
      (typeof binding !== "object" && typeof binding !== "function") ||
      binding === null ||
      typeof Reflect.get(binding, "fetch") !== "function"
    )
      throw new TnlError("sdk.configuration_invalid");
    return (request) => (binding as { fetch(request: Request): Promise<Response> }).fetch(request);
  }

  async #start(identity: EnrolledPublisher, intent: Intent): Promise<Running> {
    const current = this.#running.get(intent.service);
    if (current?.intent.id === intent.id) return current;
    if (current !== undefined) await this.#closeRun(current);
    const publication = await identity.publish(intent.service, this.#target(intent.target));
    const running = { intent, publication };
    this.#running.set(intent.service, running);
    const ended = () => {
      if (this.#running.get(intent.service) === running) this.#running.delete(intent.service);
    };
    void publication.wait().then(ended, ended);
    return running;
  }

  async #closeRun(running: Running): Promise<void> {
    await running.publication.close();
    if (this.#running.get(running.intent.service) === running)
      this.#running.delete(running.intent.service);
  }

  #result({ intent, publication }: Running): WorkerPublicationData {
    return {
      id: intent.id,
      ...(publication.url === undefined ? {} : { url: publication.url }),
      ...(publication.run === undefined ? {} : { run: publication.run }),
      ...(publication.publisherURL === undefined ? {} : { publisherURL: publication.publisherURL }),
    };
  }
}
