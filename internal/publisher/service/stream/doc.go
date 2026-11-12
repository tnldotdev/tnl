// package stream owns one service visitor's TLS and target-forwarding lifetime.
// it handles HTTP, TCP, PostgreSQL, MySQL, and Kubernetes, including cancellation,
// half-close, permission expiry, and joined request or upgrade work.
//
// the run owner supplies the selected endpoint, certificate, target trust,
// admission, and request budget. this package neither allocates service runs nor
// imports publisher or service orchestration. HTTPFrontend and RequestLimits are
// consumer-owned interfaces; implementations do not transfer their run lifetime.
package stream
