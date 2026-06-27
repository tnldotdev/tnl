export interface TnlConfig {
  server?: string;
  tunnel?: {
    host?: string;
    subdomain?: string;
    public?: boolean;
    /**
     * @maxItems 63
     */
    allowIP?: string[];
  };
  publish?: Publish;
  dev?: Dev;
}
export interface Publish {
  target?: string | number;
}
export interface Dev {
  /**
   * @minItems 1
   */
  command?: [string, ...string[]];
  port?: number;
  startupTimeout?: string;
}

/** Details about the Git worktree or project directory containing tnl.ts. */
export interface TnlWorktree {
  readonly isGit: boolean;
  readonly label: string;
  readonly name: string;
  readonly root: string;
}

/** Values available to a tnl.ts configuration factory. */
export interface TnlConfigContext {
  readonly cwd: string;
  readonly env: Readonly<Record<string, string>>;
  readonly worktree: TnlWorktree;
}

export type TnlConfigFactory = (context: TnlConfigContext) => TnlConfig | Promise<TnlConfig>;

export type TnlConfigInput = TnlConfig | TnlConfigFactory;

/** Provides type checking for an implicit-version-1 tnl.ts configuration. */
export declare function defineConfig(config: TnlConfigInput): TnlConfigInput;
