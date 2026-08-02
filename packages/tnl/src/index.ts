import { parseRuntimePayload, type ProjectMetadata } from "./internal/runtime.js";

/** Extended with service types from the generated `.tnl/project.d.ts` file. */
export interface TnlProjectMetadata {}

type RegisteredTnlProject = keyof TnlProjectMetadata extends never
  ? ProjectMetadata
  : Readonly<TnlProjectMetadata>;

type TnlProject = RegisteredTnlProject & {
  readonly runningUnderTnlDev: boolean;
};

declare const process:
  | {
      readonly env?: {
        readonly TNL_PROJECT_RUNTIME?: string;
      };
    }
  | undefined;

const serializedRuntime =
  typeof process === "undefined" ? undefined : process.env?.TNL_PROJECT_RUNTIME;

/** Project metadata added by a tnl framework integration during development. */
export const tnl = parseRuntimePayload(serializedRuntime) as TnlProject | undefined;
