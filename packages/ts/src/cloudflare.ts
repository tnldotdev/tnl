import connector from "./wasm/connector.wasm";
import type { TnlStreamConnectionRegistry } from "./project.js";
import type { Connect, DriverClient } from "./internal/connector/deployment_types.js";
import { portableOperation } from "./internal/connector/portable_operations.js";
import { loadWasm } from "./internal/connector/wasm_loader.js";

export * from "./index.js";
export { portableDeployment as deployment } from "./internal/connector/portable_operations.js";
export * from "./durable-object.worker.js";

// workerd supplies the compiled module through the static import. the default
// bundle can include both capabilities, but the connector starts only its
// own instance and joins it at deployment.close().
const loadConnector = () => loadWasm(connector);

export const connect = ((owner: object, name: string) =>
  portableOperation(owner, "connector", loadConnector).connect(
    name,
  )) as Connect<TnlStreamConnectionRegistry>;

export const client: DriverClient<TnlStreamConnectionRegistry> = (owner, name, driver) =>
  portableOperation(owner, "connector", loadConnector).client(name, {
    create: (connection) => driver.create(connection as Parameters<typeof driver.create>[0]),
    close: driver.close,
  });
