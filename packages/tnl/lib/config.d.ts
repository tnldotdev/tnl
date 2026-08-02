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

/** The Git worktree or project directory that contains tnl.config.ts. */
export interface TnlWorktree {
  readonly isGit: boolean;
  /** DNS-safe worktree label derived from this worktree and client state. */
  readonly label: string;
  readonly name: string;
  readonly root: string;
}

/** Values passed to a tnl.config.ts configuration factory. */
export interface TnlConfigContext {
  readonly cwd: string;
  readonly env: Readonly<Record<string, string>>;
  readonly worktree: TnlWorktree;
}

export type TnlConfigFactory = (context: TnlConfigContext) => TNL | Promise<TNL>;

export type TnlConfigInput = TNL | TnlConfigFactory;

/** Adds type checking to a version-1 tnl.config.ts configuration. */
export declare function defineConfig<const Config extends TnlConfigInput>(config: Config): Config;
