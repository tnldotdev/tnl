import { TnlError } from "../../errors.js";
import type { ServiceFacts } from "../../project.js";
import type { Deployment } from "./deployment_types.js";

/** one opaque public handle per owner; no public operation methods or credentials. */
export function deploymentHandles<Owner extends { close(): Promise<void> }>() {
  const owners = new WeakMap<object, Owner>();
  return {
    handle<Services extends ServiceFacts, Registry>(owner: Owner): Deployment<Services, Registry> {
      const handle = Object.freeze({ close: () => owner.close() });
      owners.set(handle, owner);
      return handle as Deployment<Services, Registry>;
    },
    get(handle: object): Owner {
      const owner = owners.get(handle);
      if (owner === undefined) throw new TnlError("sdk.configuration_invalid");
      return owner;
    },
  };
}
