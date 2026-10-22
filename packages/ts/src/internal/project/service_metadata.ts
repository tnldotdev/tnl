import { TnlError } from "../../errors.js";
import type { ProjectRuntime, ProjectServiceMetadata } from "./runtime.js";

/** absent optional services stay absent; only an unprepared project is an error. */
export function serviceMetadata(
  runtime: ProjectRuntime | undefined,
): Readonly<Record<string, ProjectServiceMetadata | undefined>> {
  if (runtime === undefined) throw new TnlError("sdk.service_unprepared");
  const services: Record<string, ProjectServiceMetadata> = Object.create(null);
  for (const [name, metadata] of Object.entries(runtime.services)) {
    if (metadata !== undefined) services[name] = metadata;
  }
  return Object.freeze(services);
}
