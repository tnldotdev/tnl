import { TnlError } from "../errors.js";
import type { ProjectRuntime, ProjectServiceMetadata } from "./runtime.js";

/** missing metadata is a preparation failure, never an invented endpoint. */
export function serviceMetadata(
  runtime: ProjectRuntime | undefined,
): Record<string, { metadata: ProjectServiceMetadata }> {
  if (runtime === undefined) throw new TnlError("sdk.service_unprepared");
  const services: Record<string, { metadata: ProjectServiceMetadata }> = Object.create(null);
  for (const [name, metadata] of Object.entries(runtime.services)) {
    if (metadata !== undefined) services[name] = Object.freeze({ metadata });
  }
  return new Proxy(Object.freeze(services), {
    get(target, key, receiver): unknown {
      if (typeof key === "string" && !Object.hasOwn(target, key))
        throw new TnlError("sdk.service_unprepared");
      return Reflect.get(target, key, receiver);
    },
  });
}
