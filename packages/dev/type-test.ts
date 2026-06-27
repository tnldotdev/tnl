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
} from "./dist/index.js";

const session: TnlDevBootstrap | null = readDevEnvironment({});
const assigned: Promise<TnlTunnelAssignment | null> = requestTunnelAssignment(
  { framework: "vite" },
  {},
);

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

export { assigned, register, session, unvalidatedURL };
