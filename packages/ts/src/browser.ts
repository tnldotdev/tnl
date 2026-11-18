import { parseRuntimePayload } from "./internal/project/runtime.js";
import { TnlError } from "./errors.js";
import { serviceMetadata } from "./internal/project/service_metadata.js";
import type { TnlRuntime } from "./internal/project/native_runtime.js";
import type { TnlStreamConnectionRegistry } from "./project.js";
import type { Connect, DriverClient, Publish } from "./internal/connector/deployment_types.js";
import type { FetchHandler } from "./internal/publisher/fetch_types.js";
import type {
  NamedPublicationOptions,
  TemporaryPublicationOptions,
} from "./internal/publisher/publication.js";
import { portableOperation } from "./internal/connector/portable_operations.js";
import { loadWasm } from "./internal/connector/wasm_loader.js";
import {
  enrollPortablePublisher,
  isEnrolledOwner,
  type EnrolledPublisher,
  type PublisherOptions,
} from "./internal/portable/enrollment.js";

export * from "./index.js";
export { portableDeployment as deployment } from "./internal/connector/portable_operations.js";
export { createBrowserPublisherStorage } from "./internal/portable/storage-browser.js";
export type {
  EnrolledPublisher,
  PublisherOptions,
  PublisherEnrollment,
} from "./internal/portable/enrollment.js";
export {
  PublisherStorageError,
  type PublisherStorage,
  type PublisherStorageErrorCode,
} from "./internal/portable/storage.js";

// resolve each asset in its operation's loader so connecting does not fetch
// or instantiate the publisher.
const loadConnector = () => loadWasm(new URL("./wasm/connector.wasm", import.meta.url));
const loadPublisher = () => loadWasm(new URL("./wasm/publisher.wasm", import.meta.url));

export function publisher(options: PublisherOptions = {}) {
  return enrollPortablePublisher(options, loadPublisher);
}

export const connect = ((owner: object, name: string) =>
  portableOperation(owner, "connector", loadConnector).connect(
    name,
  )) as Connect<TnlStreamConnectionRegistry>;

export const client: DriverClient<TnlStreamConnectionRegistry> = (owner, name, driver) =>
  portableOperation(owner, "connector", loadConnector).client(name, {
    create: (connection) => driver.create(connection as Parameters<typeof driver.create>[0]),
    close: driver.close,
  });

export const publish: Publish<TnlStreamConnectionRegistry> & EnrolledPublisherPublish = async (
  owner: object,
  first: string | FetchHandler,
  second?: FetchHandler | TemporaryPublicationOptions,
  third?: NamedPublicationOptions,
) => {
  if (isEnrolledOwner(owner)) {
    if (typeof first !== "string" || typeof second !== "function")
      throw new TnlError("sdk.configuration_invalid");
    return owner.publish(first, second, third);
  }
  const operations = portableOperation(owner, "publisher", loadPublisher);
  return typeof first === "string"
    ? operations.publish(first, second as FetchHandler, third)
    : operations.publish(first, second as TemporaryPublicationOptions | undefined);
};

type EnrolledPublisherPublish = (
  owner: EnrolledPublisher,
  name: string,
  handler: FetchHandler,
  options?: NamedPublicationOptions,
) => ReturnType<EnrolledPublisher["publish"]>;

declare const process: { readonly env?: { readonly TNL_PROJECT_RUNTIME?: string } } | undefined;

const runtime = parseRuntimePayload(
  typeof process === "undefined" ? undefined : process.env?.TNL_PROJECT_RUNTIME,
);

/** Browser-safe project metadata; listener registration is server-only. */
export const tnl = Object.freeze({
  ...runtime,
  get services() {
    return serviceMetadata(runtime);
  },
  port: 3000,
  dev: runtime?.dev ?? false,
}) as Omit<TnlRuntime, "prepare">;
