import { tnl, type PublisherFile, type PublisherID, type OpenOptions } from "@tnldotdev/tnl";

const file: PublisherFile = { publisherFile: "/private/publisher.json" };
const stored: PublisherID = { publisherID: `pub_${"A".repeat(22)}` };
const handler = () => new Response("app");
void tnl.open(handler);
void tnl.open(handler, file);
void tnl.open(handler, { ...stored, stateDir: "/private/client", access: { ip: ["127.0.0.1"] } });
void tnl.prepare({ service: "web", directory: "/project", stateDir: "/private/client" });

// @ts-expect-error a publisher file and stored publisher ID are separate choices.
const both: OpenOptions = { publisherFile: "/private/publisher.json", publisherID: "id" };
void both;
// @ts-expect-error enrollment is an explicit native setup operation.
void tnl.open(handler, { enrollmentKey: "key" });
// @ts-expect-error publication credentials were removed.
void tnl.open(handler, { credential: "old" });
// @ts-expect-error use access.ip for visitor IP settings.
void tnl.open(handler, { allowIP: ["127.0.0.1"] });
