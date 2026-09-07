export interface TNL {
  server?: string;
  team?: string;
  tunnel?: {
    host?: string;
    subdomain?: string;
    public?: boolean;
    ephemeral?: boolean;
    /**
     * @maxItems 63
     */
    allowIP?: string[];
  };
  publish?: Publish;
  dev?: Dev;
  services?: {
    [k: string]: {
      directory?: string;
      server?: string;
      team?: string;
      tunnel?: {
        host?: string;
        subdomain?: string;
        public?: boolean;
        ephemeral?: boolean;
        /**
         * @maxItems 63
         */
        allowIP?: string[];
      };
      publish?: Publish;
      dev?: Dev;
    };
  };
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

/** Details about the Git worktree or project directory containing tnl.config.ts. */
export interface TnlWorktree {
  readonly isGit: boolean;
  /** DNS-safe name keyed to this worktree and client state directory. */
  readonly label: string;
  readonly name: string;
  readonly root: string;
}

/** Values available to a tnl.config.ts configuration factory. */
export interface TnlConfigContext {
  readonly cwd: string;
  readonly env: Readonly<Record<string, string>>;
  readonly worktree: TnlWorktree;
}

export type TnlConfigFactory = (context: TnlConfigContext) => TNL | Promise<TNL>;

export type TnlConfigInput = TNL | TnlConfigFactory;

/** Provides type checking for an implicit-version-1 tnl.config.ts configuration. */
export declare function defineConfig<const Config extends TnlConfigInput>(config: Config): Config;
