// package local owns the project-scoped local publisher process and its API.
// it composes app registrations, invocation operations, and localapi, and joins
// their work during shutdown. localapi does not import this process owner.
package local
