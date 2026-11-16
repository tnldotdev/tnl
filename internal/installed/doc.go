// package installed owns installed publisher and connector job definitions,
// operating-system service setup, reconciliation, supervision, and joined stop.
// it composes publisher operations and caller-supplied connector operations.
//
// this is a process composition owner, not a shared client facility. auth, state,
// project, and control clients remain below it in client and must not import it.
// deployment job runners compose deployment-owned assignment publication; foreground
// callers can use that publisher operation without an installed job or registry.
package installed
