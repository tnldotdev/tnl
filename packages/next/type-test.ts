import { withTnl } from "./dist/index.js";

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

export { asynchronousFactory, objectConfig, promisedConfig, synchronousFactory };
