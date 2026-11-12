// package httpaccess owns run-bound visitor policy refresh, browser handoffs,
// token renewal, cookie handling, and local HTTP authorization. public URL and
// service run owners compose it and join its workers before retiring a run.
// it never imports either run orchestrator or owns accepted visitor connections.
package httpaccess
