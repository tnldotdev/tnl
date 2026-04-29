import type { Plugin } from "vite";
import tnl from "./dist/index.js";

const plugin: Plugin = tnl();

// @ts-expect-error tnl settings belong in vite.config.ts.
tnl({});

export default plugin;
