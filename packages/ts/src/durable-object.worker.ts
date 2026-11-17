import module from "./wasm/publisher.wasm";
import {
  DurableObjectPublisher,
  type DurableObjectPublisherState,
  type DurableObjectWasmPublisherOptions,
} from "./durable-object.js";
import { durablePublisherDeployment } from "./internal/portable/durable-deployment.js";

export {
  createDurableObjectPublisherStorage,
  createPublisherStorageHost,
  PublisherStorageError,
} from "./durable-object.js";
export type {
  DurableObjectPublisher,
  DurableObjectPublisherState,
  DurableObjectWasmPublisherOptions,
  DurablePublicationConfiguration,
  PublisherSQLiteStorage,
  PublisherStorage,
  PublisherStorageHost,
  PublisherStorageErrorCode,
} from "./durable-object.js";

/** workerd reuses compiled code, not live runtimes or request-scoped sockets. */
export function durablePublisher(
  state: DurableObjectPublisherState,
  options: DurableObjectWasmPublisherOptions,
): DurableObjectPublisher {
  return new DurableObjectPublisher(state, {
    ...options,
    createDeployment: (context) => durablePublisherDeployment(context, module),
  });
}
