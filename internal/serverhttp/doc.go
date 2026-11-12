// package serverhttp owns shared server HTTP mechanics: bounded JSON requests,
// problem responses, control cookies, and private cluster bearer authentication.
// control, ingress, and relay API adapters use it. it owns no saved application
// service, database state, publisher identity, or authorization decision.
package serverhttp
