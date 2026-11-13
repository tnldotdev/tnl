import type { ResolveHook } from "node:module";

// the HTTP-only entry point must load without Node built-ins, even transitively.
export const resolve: ResolveHook = async (specifier, context, nextResolve) => {
  if (specifier.startsWith("node:")) throw new Error(`HTTP import reached ${specifier}`);
  return nextResolve(specifier, context);
};
