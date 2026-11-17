package state

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
)

func auditSourceDigest(t *testing.T, d *Database, service, source string) string {
	t.Helper()
	key, err := d.readServiceIPKey(t.Context(), controlstatedb.New(d.pool), service, serviceAuditIPKeyPurpose)
	if err != nil || len(key) != 32 {
		t.Fatal("missing private audit key", err)
	}
	digest, err := ippolicy.HashAddress([32]byte(key), netip.MustParseAddr(source))
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func publicVisitorSourceDigest(t *testing.T, d *Database, service, source string) string {
	t.Helper()
	digest, err := d.serviceIPDigest(t.Context(), controlstatedb.New(d.pool), service, publicVisitorIPKeyPurpose, netip.MustParseAddr(source))
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestServiceAuditPersistenceRejectsRawSources(t *testing.T) {
	event := serviceaudit.Event{EventType: "connection.open", SourceIP: "192.0.2.1"}
	if _, err := insertServiceAuditBatch(t.Context(), nil, []serviceaudit.Event{event}, time.Now()); !errors.Is(err, serviceaudit.ErrInvalid) {
		t.Fatal("raw source reached persistence", err)
	}
	encoded, err := json.Marshal(event)
	if err != nil || strings.Contains(string(encoded), "192.0.2.1") || strings.Contains(string(encoded), "source_ip") {
		t.Fatal("transient source reached the audit API", err)
	}
}
