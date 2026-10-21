import type * as SDK from "@tnldotdev/tnl";

declare const tnlModule: typeof SDK;

const database = tnlModule.tnl.connect("db");
database.host satisfies "127.0.0.1";
database.ssl.servername satisfies string;
database satisfies PromiseLike<SDK.TnlConnectionRegistry["postgres"]>;
({ ...database, user: "app", database: "app" }) satisfies import("pg").PoolConfig;
// @ts-expect-error CommonJS uses the same exact generated service registry.
tnlModule.tnl.connect("missing");
// @ts-expect-error CommonJS SQL settings have no HTTP fetch method.
void database.fetch;
// @ts-expect-error CommonJS settings are read-only too.
database.port = 5432;
