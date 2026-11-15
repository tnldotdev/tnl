// package ingress accepts public visitor connections and forwards each to one
// eligible publisher path using current service admission and connected relays.
// it may retry a relay only before sending the first visitor byte. visitor TLS
// ends at the publisher. control clients supply state; this package never opens
// PostgreSQL or imports control's state or HTTP handlers.
package ingress
