import * as z from "zod";
import { TnlError } from "../../errors.js";
import { projectRuntimeSchema } from "../project/runtime.js";
import { parseValue } from "../validation.js";
import {
  hostnameSchema,
  httpsOriginSchema,
  registrationIDSchema,
  serviceNameSchema,
} from "../values.js";
import type { EndpointSelection, RuntimeEndpoint } from "./local.js";
import type { ServiceCertificate } from "../publication_certificate.js";

export interface RegistrationRuntime {
  start(
    directory: string,
    binary?: string,
    selection?: EndpointSelection,
    signal?: AbortSignal,
  ): Promise<RuntimeEndpoint>;
  request(
    endpoint: RuntimeEndpoint,
    operation: string,
    body?: unknown,
    signal?: AbortSignal,
  ): Promise<unknown>;
}

export interface RegistrationShutdown {
  readonly deadline: string;
  readonly signal: AbortSignal;
}

const assignmentSchema = z
  .strictObject({
    version: z.literal(1),
    registration_id: registrationIDSchema,
    service: serviceNameSchema,
    hostname: z.union([hostnameSchema, z.literal("")]),
    public_url: z.union([httpsOriginSchema, z.literal("")]),
    project: projectRuntimeSchema,
  })
  .refine(({ service, hostname, public_url, project }) => {
    const metadata = project.services[service];
    return (
      project.dev &&
      (hostname === ""
        ? public_url === "" && metadata === undefined
        : metadata?.protocol === "http" &&
          metadata.hostname === hostname &&
          metadata.url === `https://${hostname}` &&
          public_url === (metadata.public ? metadata.url : ""))
    );
  })
  .transform(({ registration_id, service, hostname, public_url, project }) => ({
    registrationID: registration_id,
    service,
    hostname: hostname === "" ? undefined : hostname,
    publicURL: public_url === "" ? undefined : public_url,
    project,
  }))
  .readonly();
export type Assignment = z.output<typeof assignmentSchema>;

export function parseAssignment(value: unknown): Assignment {
  return parseValue(assignmentSchema, value, "sdk.response_invalid");
}

const registrationSchema = z
  .strictObject({
    version: z.literal(1),
    registration_id: registrationIDSchema,
    owner: z.string(),
    target: z.string(),
  })
  .readonly();
type Registration = {
  readonly version: 1;
  readonly registration_id: string;
  readonly owner: string;
  readonly target?: string;
};
type Acquisition =
  | {
      readonly kind: "configured";
      readonly request: Readonly<{ owner: string; [key: string]: unknown }>;
      readonly target?: string;
    }
  | {
      readonly kind: "invocation";
      readonly request: Readonly<{ owner: string; target: string; [key: string]: unknown }>;
    };

export function recoverableRegistration(cause: unknown): boolean {
  return (
    cause instanceof TnlError &&
    (cause.code === "sdk.dev_unavailable" || cause.code === "sdk.registration_stale")
  );
}

export function publicationCleanupFailed(cause: unknown): boolean {
  return cause instanceof TnlError && cause.code === "sdk.publication_cleanup_failed";
}

// owns one native acquisition and its exact cleanup identity. callers serialize
// mutations and join their renewal/observation loops before unregistering.
export class NativeRegistration {
  private currentEndpoint: RuntimeEndpoint | undefined;
  private current: Registration | undefined;
  private uncertain = false;
  private unregisterReplyLost = false;
  private readonly acquisition: Acquisition;
  private readonly runtime: RegistrationRuntime;
  private readonly directory: string;
  private readonly selection: EndpointSelection;

  constructor(
    runtime: RegistrationRuntime,
    directory: string,
    selection: EndpointSelection,
    acquisition: Acquisition,
  ) {
    // capture nested policy and deployment inputs, not caller-owned objects.
    this.acquisition = structuredClone(acquisition);
    this.runtime = runtime;
    this.directory = directory;
    this.selection = {
      ...selection,
      ...(selection.environment === undefined ? {} : { environment: { ...selection.environment } }),
    };
  }

  get endpoint(): RuntimeEndpoint {
    if (this.currentEndpoint === undefined) throw new TnlError("sdk.registration_stale");
    return this.currentEndpoint;
  }

  get registration(): Registration | undefined {
    return this.current;
  }

  async discover(signal?: AbortSignal): Promise<void> {
    this.currentEndpoint = await this.runtime.start(
      this.directory,
      undefined,
      this.selection,
      signal,
    );
  }

  async acquire(signal?: AbortSignal): Promise<Assignment | undefined> {
    this.uncertain = true;
    try {
      const { kind, request } = this.acquisition;
      if (kind === "configured") {
        const assignment = parseAssignment(
          await this.runtime.request(this.endpoint, "prepare", structuredClone(request), signal),
        );
        // retain the acknowledgment before caller-specific endpoint validation.
        this.current = {
          version: 1,
          registration_id: assignment.registrationID,
          owner: request.owner,
          ...(this.acquisition.kind === "configured" && this.acquisition.target !== undefined
            ? { target: this.acquisition.target }
            : {}),
        };
        this.uncertain = false;
        return assignment;
      }
      const registration = parseValue(
        registrationSchema,
        await this.runtime.request(
          this.endpoint,
          "publications/register",
          structuredClone(request),
          signal,
        ),
        "sdk.response_invalid",
      );
      if (registration.owner !== request.owner || registration.target !== request.target)
        throw new TnlError("sdk.response_invalid");
      this.current = registration;
      this.uncertain = false;
      return undefined;
    } catch (cause) {
      if (
        cause instanceof TnlError &&
        !["sdk.dev_unavailable", "sdk.registration_stale", "sdk.response_invalid"].includes(
          cause.code,
        )
      )
        this.uncertain = false;
      throw cause;
    }
  }

  async bind(target: string, signal?: AbortSignal): Promise<void> {
    if (this.current === undefined) throw new TnlError("sdk.registration_stale");
    this.current = { ...this.current, target };
    await this.runtime.request(this.endpoint, "register", this.current, signal);
  }

  async renew(signal?: AbortSignal, certificate?: ServiceCertificate): Promise<void> {
    if (certificate !== undefined && this.acquisition.kind !== "invocation")
      throw new TnlError("sdk.capability_unsupported");
    const request =
      certificate === undefined
        ? this.current
        : {
            ...this.current,
            certificate: {
              certificate_pem: certificate.certificatePEM,
              private_key_pem: certificate.privateKeyPEM,
            },
          };
    await this.runtime.request(this.endpoint, "renew", request, signal);
  }

  async status(signal?: AbortSignal): Promise<unknown> {
    return this.runtime.request(this.endpoint, "status", undefined, signal);
  }

  async unregister(
    budget: RegistrationShutdown,
    retry?: { readonly pause: (milliseconds: number, signal?: AbortSignal) => Promise<void> },
  ): Promise<void> {
    budget.signal.throwIfAborted();
    const attempts = retry === undefined ? 1 : 3;
    if (this.uncertain && this.acquisition.kind === "configured" && this.current === undefined)
      throw new TnlError("sdk.dev_unavailable");
    // only invocation acquisition has an exact idempotent replay contract.
    for (let attempt = 0; this.uncertain && this.acquisition.kind === "invocation"; attempt++) {
      try {
        await this.acquire(budget.signal);
      } catch (cause) {
        if (attempt + 1 >= attempts || !unavailable(cause)) throw cause;
        await this.discover(budget.signal);
      }
    }
    if (this.current === undefined) return;
    for (let attempt = 0; ; attempt++) {
      try {
        await this.runtime.request(
          this.endpoint,
          "unregister",
          { ...this.current, shutdown_deadline: budget.deadline },
          budget.signal,
        );
        break;
      } catch (cause) {
        if (publicationCleanupFailed(cause)) {
          this.current = undefined;
          this.uncertain = false;
          this.unregisterReplyLost = false;
        }
        if (
          this.unregisterReplyLost &&
          cause instanceof TnlError &&
          cause.code === "sdk.registration_stale"
        )
          throw new TnlError("sdk.dev_unavailable");
        if (
          unavailable(cause) ||
          (cause instanceof TnlError && cause.code === "sdk.response_invalid")
        )
          this.unregisterReplyLost = true;
        if (attempt + 1 >= attempts || !unavailable(cause)) throw cause;
        await retry?.pause(100, budget.signal);
      }
    }
    this.current = undefined;
    this.uncertain = false;
    this.unregisterReplyLost = false;
  }
}

function unavailable(cause: unknown): boolean {
  return cause instanceof TnlError && cause.code === "sdk.dev_unavailable";
}
