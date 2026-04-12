// Package tailtransport carries lease-scoped TCP streams over Tailcat. Server
// runs on the agent beside the local target, while hosted ingress owns one
// reusable Dialer and opens streams to the lease's fixed TCP port.
//
// Endpoint values contain only a server public key and an operator-defined
// relay profile name. The package resolves and snapshots that profile locally;
// raw Tailcat connection blobs never cross the untrusted protocol boundary.
//
// A transport starts once, drains by rejecting new streams while existing
// streams finish, and closes terminally. Close cancels context-aware calls and
// joins all admitted Tailcat operations before shutting down the network stack.
package tailtransport
