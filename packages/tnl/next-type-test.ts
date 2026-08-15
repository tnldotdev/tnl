import { withTnl } from "@tnldotdev/tnl/next";

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
withTnl({}, { allowAllIPs: true });

export { asynchronousFactory, objectConfig, promisedConfig, synchronousFactory };
