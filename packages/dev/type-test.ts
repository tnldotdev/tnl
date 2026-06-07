import {
  publicTunnelEnvironment,
  readDevEnvironment,
  registerLocalPort,
  requestTunnelAssignment,
  type TnlDevBootstrap,
  type TnlHostname,
  type TnlPublicURL,
  type TnlTunnelAssignment,
  type TnlTunnelID,
  type TnlTunnelOptions,
  type TnlTunnelOptionsInput,
  type TnlWorktree,
} from "./dist/index.js";

const session: TnlDevBootstrap | null = readDevEnvironment({});
const options: TnlTunnelOptions = {
  controlURL: "https://tnl.example.com",
  host: "agent.example.com",
  allowIP: ["198.51.100.0/24"],
  allowCurrentIP: true,
};
const dynamicOptions: TnlTunnelOptionsInput = async ({ cwd, env, worktree }) => ({
  ...options,
  host: `${env.USER ?? worktree.label}.${cwd.length}.example.com`,
});
const assigned: Promise<TnlTunnelAssignment | null> = requestTunnelAssignment(
  { framework: "vite", options: dynamicOptions },
  {},
);
const worktree: TnlWorktree = {
  isGit: true,
  label: "feature-auth",
  name: "feature-auth",
  root: "/worktrees/feature-auth",
};

if (session !== null) {
  session.socket satisfies string;
}

async function register(assignment: TnlTunnelAssignment): Promise<void> {
  const environment = publicTunnelEnvironment(assignment, "PUBLIC_");
  environment.PUBLIC_TNL_HOSTNAME satisfies TnlHostname;
  environment.PUBLIC_TNL_TUNNEL_ID satisfies TnlTunnelID;
  environment.PUBLIC_TNL_URL satisfies TnlPublicURL;
  await registerLocalPort(assignment, 5173);
}

// @ts-expect-error Public URLs must come from tnl validation.
const unvalidatedURL: TnlPublicURL = "https://demo.tnl.dev";

export { assigned, options, register, session, unvalidatedURL, worktree };
