import type { Plugin } from "vite";
import tnl from "@tnldotdev/tnl/vite";
import { expectTypeOf, test } from "vitest";

test("Vite returns its native plugin type", () => {
  expectTypeOf(tnl()).toEqualTypeOf<Plugin>();

  // @ts-expect-error tnl configuration belongs in the project config file.
  tnl({ access: "anonymous" });
});
