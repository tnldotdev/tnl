import { TnlError } from "../../errors.js";
import type { ServiceFacts, TnlStreamConnectionRegistry } from "../../project.js";
import type { Deployment } from "./deployment_types.js";
import { deploymentHandles } from "./operation_handles.js";
import {
  createStreamClient,
  type RuntimeKind,
  type StreamClientOptions,
  type StreamDeployment,
} from "./wasm_client.js";
import type { WasmRuntime } from "./wasm_loader.js";

export type PortableDeployment<Services extends ServiceFacts> = Deployment<
  Services,
  TnlStreamConnectionRegistry
>;

type Loader = () => Promise<WasmRuntime>;
const owners = deploymentHandles<
  StreamDeployment<ServiceFacts> & {
    use(kind: RuntimeKind, loader: Loader): void;
  }
>();

export function portableDeployment<const Services extends ServiceFacts = Record<never, never>>(
  name: string,
  options: StreamClientOptions<Services>,
): PortableDeployment<Services> {
  const loaders = new Map<RuntimeKind, Loader>();
  const owner = createStreamClient(options, (kind) => {
    const load = loaders.get(kind);
    if (load === undefined) throw new TnlError("sdk.capability_unsupported");
    return load();
  }).deployment(name);
  return owners.handle({
    ...(owner as StreamDeployment<ServiceFacts>),
    use(kind, load) {
      if (!loaders.has(kind)) loaders.set(kind, load);
    },
  });
}

export function portableOperation(owner: object, kind: RuntimeKind, load: Loader) {
  const operations = owners.get(owner);
  operations.use(kind, load);
  return operations;
}
