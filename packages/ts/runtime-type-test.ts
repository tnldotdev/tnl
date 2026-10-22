import { tnl } from "@tnldotdev/tnl";
import type { TnlConnectionRegistry } from "@tnldotdev/tnl";

declare const database: TnlConnectionRegistry["postgres"];
({
  ...database,
  user: "app",
  database: "app",
  password: "application-owned",
}) satisfies import("pg").PoolConfig;
({
  dialect: "postgresql",
  dbCredentials: { ...database, user: "app", database: "app", password: "application-owned" },
}) satisfies import("drizzle-kit").Config;
({
  ...database,
  user: "app",
  database: "app",
  password: "application-owned",
  max: 5,
  prepare: false,
}) satisfies import("postgres").Options<{}>;
declare const mysql: TnlConnectionRegistry["mysql"];
({
  ...mysql,
  user: "app",
  database: "app",
  password: "application-owned",
}) satisfies import("mysql2").ConnectionOptions;

tnl.port satisfies number;
tnl.dev satisfies boolean;
const service = tnl.services.anyService;
// @ts-expect-error ungenerated metadata is read-only too.
tnl.services.anyService = undefined;
const connection = tnl.connect("any-service");
// @ts-expect-error an ungenerated service has a protocol union, never any.
void connection.ssl;
if ("ssl" in connection) {
  connection.host satisfies string;
  connection.ssl.rejectUnauthorized satisfies true;
  // @ts-expect-error narrowing a SQL connection does not add HTTP settings.
  void connection.fetch;
}
if (service) {
  service.hostname satisfies string;
  service.port satisfies number;
  service.public satisfies boolean;
  if (service.protocol === "http" || service.protocol === "kubernetes") {
    service.url satisfies `https://${string}`;
  }
  // @ts-expect-error browser-safe metadata never contains native TLS keys.
  void service.ssl;
}
// @ts-expect-error there is no separate server entrypoint.
void import("@tnldotdev/tnl/server");
