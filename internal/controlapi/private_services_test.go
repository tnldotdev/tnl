package controlapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type privateTicketResponseStore struct {
	PublicURLStore
	privateVisitorStore
	issued controlstate.PrivateServiceTicket
}

func (s privateTicketResponseStore) IssuePrivateServiceTicket(_ context.Context, serviceID, sessionID, identityID string, _ time.Time) (controlstate.PrivateServiceTicket, error) {
	if serviceID != s.issued.PrivateServiceID || sessionID != s.issued.ConnectorSessionID || identityID != s.issued.IdentityID {
		panic("ticket issued for the wrong authenticated scope")
	}
	return s.issued, nil
}

func TestPrivateConnectionPublicKeyUsesExactLowercaseHexContract(t *testing.T) {
	service, _ := opaqueid.New(opaqueid.PrivateServicePrefix)
	session, _ := opaqueid.New(opaqueid.PrivateConnectorSessionPrefix)
	key := bytes.Repeat([]byte{0xAB}, 32)
	store := privateTicketResponseStore{issued: controlstate.PrivateServiceTicket{
		PrivateServiceID: service, ConnectorSessionID: session, IdentityID: testPublicURLReadPrincipal().identityID,
		PrivateRunID: "psrun_0123456789ABCDEFGHIJKL", SourceIP: netip.MustParseAddr("192.0.2.1"),
		StreamPublicKey: key, Ticket: "ticket-secret", ExpiresAt: time.Now().Add(time.Minute), RunNumber: 1,
	}}
	h := &handler{store: store, authorizer: &recordingAuthorizer{principal: testPublicURLReadPrincipal()}}
	r := httptest.NewRequest(http.MethodPost, "/v1/private-services/"+service+"/connect", strings.NewReader(`{"connector_session_id":"`+session+`"}`))
	r.Header.Set("Authorization", "Bearer access-token")
	w := httptest.NewRecorder()
	h.CreatePrivateServiceTicket(w, r, service)
	if w.Code != 201 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("ticket response: %d %s", w.Code, w.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	encoded, ok := raw["stream_public_key"].(string)
	if !ok || len(encoded) != 64 || encoded != hex.EncodeToString(key) || encoded != strings.Repeat("ab", 32) {
		t.Fatalf("stream_public_key = %v, want lowercase 64-character hex", raw["stream_public_key"])
	}
	var parsed controlv1.PrivateServiceConnection
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil || parsed.StreamPublicKey != encoded {
		t.Fatalf("generated response contract = %+v: %v", parsed, err)
	}
}
