// Package tailtransport carries session-scoped TCP streams over Tailcat. Server
// runs on the publisher beside the local target, while hosted ingress owns one
// reusable Dialer and opens streams to the session's fixed TCP port.
//
// TransportDescriptor values contain only a server public key and an operator-defined
// relay region name. The package resolves and snapshots that relay region locally;
// raw Tailcat connection blobs never cross the untrusted protocol boundary.
//
// A transport starts once, drains by rejecting new streams while existing
// streams finish, and closes terminally. Close cancels context-aware calls and
// joins all admitted Tailcat operations before shutting down the network stack.
package tailtransport
