import { withTnl, type NextConfigFactory } from "@tnldotdev/tnl/next";
import { expectTypeOf, test } from "vitest";

test("Next accepts objects, promises, and synchronous or asynchronous factories", () => {
  const objectConfig = withTnl({ reactStrictMode: true });
  const promisedConfig = withTnl(Promise.resolve({ reactStrictMode: true }));
  const synchronousFactory = withTnl((_phase, { defaultConfig }) => ({
    ...defaultConfig,
    reactStrictMode: true,
  }));
  const asynchronousFactory = withTnl(async (_phase, { defaultConfig }) => ({
    ...defaultConfig,
    allowedDevOrigins: ["existing.example"],
  }));

  // @ts-expect-error tnl configuration belongs in the project config file.
  withTnl({}, { access: "anonymous" });

  expectTypeOf(asynchronousFactory).toEqualTypeOf<NextConfigFactory>();
  expectTypeOf(objectConfig).toEqualTypeOf<NextConfigFactory>();
  expectTypeOf(promisedConfig).toEqualTypeOf<NextConfigFactory>();
  expectTypeOf(synchronousFactory).toEqualTypeOf<NextConfigFactory>();
});
