// package relay owns authenticated publisher connections, local reservations,
// connector delivery, and visitor streams for one leased relay process. control
// authorizes durable claims; this package validates current claims and joins
// local stream cleanup. it never imports control state or terminates visitor TLS.
package relay
