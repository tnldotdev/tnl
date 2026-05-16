import {
  readDevEnvironment,
  registerTarget,
  requestTunnelAssignment,
  type TnlDevBootstrap,
  type TnlOptions,
  type TnlOptionsInput,
  type TnlTunnelAssignment,
  type TnlWorktree,
} from "./dist/index.js";

const session: TnlDevBootstrap | null = readDevEnvironment({});
const options: TnlOptions = {
  server: "https://tnl.example.com",
  name: "agent.example.com",
  allowIP: ["198.51.100.0/24"],
  allowCurrentIP: true,
};
const dynamicOptions: TnlOptionsInput = async ({ cwd, env, worktree }) => ({
  ...options,
  name: `${env.USER ?? worktree.label}.${cwd.length}.example.com`,
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
  await registerTarget(assignment, 5173);
}

export { assigned, options, register, session, worktree };
