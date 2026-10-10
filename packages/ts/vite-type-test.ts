import type { Plugin } from "vite";
import tnl from "@tnldotdev/tnl/vite";

const plugin: Plugin = tnl();

// @ts-expect-error tnl configuration belongs in the project config file.
tnl({ allowAllIPs: true });

export { plugin };
