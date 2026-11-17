import module from "./wasm/tnl.wasm";
import {
  DurableObjectPublisher,
  type DurableObjectPublisherState,
  type DurableObjectWasmPublisherOptions,
} from "./durable-object.js";
import { durablePublisherDeployment } from "./internal/portable/durable-deployment.js";

export {
  DurableObjectPublisher,
  createDurableObjectPublisherStorage,
  createPublisherStorageHost,
  PublisherStorageError,
} from "./durable-object.js";
export type {
  DurableObjectPublisherState,
  DurableObjectWasmPublisherOptions,
  DurableObjectPublisherOptions,
  DurablePublicationConfiguration,
  DurablePublisherDeployment,
  PublisherSQLiteStorage,
  PublisherStorage,
  PublisherStorageHost,
  PublisherStorageErrorCode,
} from "./durable-object.js";

/** workerd reuses compiled code, not live runtimes or request-scoped sockets. */
export function createDurableObjectPublisher(
  state: DurableObjectPublisherState,
  options: DurableObjectWasmPublisherOptions,
): DurableObjectPublisher {
  return new DurableObjectPublisher(state, {
    ...options,
    createDeployment: (context) => durablePublisherDeployment(context, module),
  });
}
