// negative type specification against the actual built SDK, not a proposal model.
import { tnl } from "@tnldotdev/tnl";
// @ts-expect-error the clean break must remove public publisher-group descriptor types.
import type { TnlGroupConnection } from "@tnldotdev/tnl";
// @ts-expect-error group client types are not a second public selection API.
import type { TnlGroupClient } from "@tnldotdev/tnl";
// @ts-expect-error descriptor options are removed rather than forwarded.
import type { TnlGroupClientOptions } from "@tnldotdev/tnl";
// @ts-expect-error no ambiently typed group-client escape hatch remains.
import type { TnlGroupClientForConfig } from "@tnldotdev/tnl";

export type RetiredClient = TnlGroupClient;
export type RetiredOptions = TnlGroupClientOptions;
export type RetiredConfiguredClient = TnlGroupClientForConfig<{}>;

declare const oldDescriptor: TnlGroupConnection;
declare const token: () => Promise<string>;

// @ts-expect-error the old descriptor/workload overload must be removed, not wrapped.
tnl.client({ connection: oldDescriptor, workload: { name: "monitor", token } });
