/** Internal distribution catalog shared by the launcher and release scripts.
 * Node architecture names belong here; Go artifact paths and versions do not.
 * Entries retain native publish order. This module is not a public package export.
 */
export const nativeTargets = Object.freeze(
  [
    { platform: "darwin", architecture: "arm64", packageName: "@tnldotdev/tnl-darwin-arm64" },
    { platform: "darwin", architecture: "x64", packageName: "@tnldotdev/tnl-darwin-x64" },
    { platform: "linux", architecture: "arm64", packageName: "@tnldotdev/tnl-linux-arm64" },
    { platform: "linux", architecture: "x64", packageName: "@tnldotdev/tnl-linux-x64" },
  ].map((target) => Object.freeze(target)),
);
