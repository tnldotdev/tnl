// package publisher owns HTTP public URL publish runs and their visitor server.
// it joins relay sessions, certificate renewal, request admission, and feedback.
// httpaccess and requestlimit supply browser access and per-run request budgets
// shared with saved HTTP services. service owns its run and certificate lifetime;
// service/stream owns native visitor TLS and protocol forwarding. none of those
// owners depends on this public URL orchestrator.
package publisher
