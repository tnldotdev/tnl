export type NativeArchitecture = "arm64" | "x64";
export type NativePlatform = "darwin" | "linux";

export interface NativeTarget {
  readonly architecture: NativeArchitecture;
  readonly packageName: `@tnldotdev/tnl-${NativePlatform}-${NativeArchitecture}`;
  readonly platform: NativePlatform;
}

const targets = [
  { platform: "darwin", architecture: "arm64", packageName: "@tnldotdev/tnl-darwin-arm64" },
  { platform: "darwin", architecture: "x64", packageName: "@tnldotdev/tnl-darwin-x64" },
  { platform: "linux", architecture: "arm64", packageName: "@tnldotdev/tnl-linux-arm64" },
  { platform: "linux", architecture: "x64", packageName: "@tnldotdev/tnl-linux-x64" },
] satisfies NativeTarget[];

/** Internal distribution catalog shared by the launcher and release scripts. */
export const nativeTargets: readonly Readonly<NativeTarget>[] = Object.freeze(
  targets.map((target) => Object.freeze(target)),
);
