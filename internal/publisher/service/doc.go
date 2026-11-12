// package service owns a saved service run: preparation, certificates, two
// publisher connection slots, heartbeats, connector peers, and joined cleanup.
// client/state retains protected keys and the certificate cache; control grants
// authority to the exact run. cached material never grants permission to serve.
//
// stream owns one accepted visitor's TLS, protocol negotiation, target connection,
// and expiry. the run supplies current admission and shares its request budget
// across streams. httpaccess supplies the shared browser and visitor policy
// implementation; requestlimit owns the per-run HTTP budget. neither service
// nor its stream child imports the public URL orchestrator in publisher.
package service
