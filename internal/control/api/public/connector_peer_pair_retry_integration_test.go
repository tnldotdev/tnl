package public

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// a lost reply cannot allocate another owner, key, or replacement. use the real
// clients and handler after PostgreSQL commits, for devices and workloads alike.
func assertNativeHTTPCommittedResponseRecovery(t *testing.T, conn *pgx.Conn, sourceServer *httptest.Server, bearer, service string, template controlv1.ConnectorPeerPairRequest, sign func([]byte) []byte) {
	t.Helper()
	ctx := t.Context()
	var mu sync.Mutex
	var requests, responses [][]byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		committed := httptest.NewRecorder()
		sourceServer.Config.Handler.ServeHTTP(committed, r)
		mu.Lock()
		requests = append(requests, body)
		responses = append(responses, bytes.Clone(committed.Body.Bytes()))
		attempt := len(requests)
		mu.Unlock()
		if committed.Code == http.StatusOK && attempt <= 3 {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		for key, values := range committed.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(committed.Code)
		_, _ = w.Write(committed.Body.Bytes())
	}))
	defer server.Close()
	api, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken(bearer))
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		DeviceID   string `json:"device_id"`
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(template.Source, &source); err != nil {
		t.Fatal(err)
	}
	prepare := func(body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
		if source.DeviceID != "" {
			return api.PrepareDeviceConnectorPeerPair(ctx, service, source.DeviceID, body)
		}
		return api.PrepareWorkloadConnectorPeerPair(ctx, service, source.Credential, body)
	}
	request := template
	request.IdempotencyKey, request.RequestedAt = "http-committed-response-loss", time.Now().UTC().Truncate(time.Microsecond)
	var pair controlv1.ConnectorPeerPair
	defer func() {
		if _, err := conn.Exec(ctx, `DELETE FROM control.connector_peer_pairs WHERE service_run_id=$1 AND owner_key=$2`, request.ServiceRunId, request.IdempotencyKey); err != nil {
			t.Error(err)
		}
	}()
	for _, action := range []controlv1.ConnectorPeerPairRequestAction{"create", "replace"} {
		if action == "replace" {
			priorID, priorGeneration := pair.PairId, pair.DeliveryGeneration
			request.Action, request.PreviousPairId, request.PreviousGeneration = action, &priorID, &priorGeneration
			request.RequestedAt = time.Now().UTC().Truncate(time.Microsecond)
		}
		message, err := controlv1.ConnectorPeerPairProofMessage(service, request)
		if err != nil {
			t.Fatal(err)
		}
		request.Signature = base64.RawURLEncoding.EncodeToString(sign(message))
		mu.Lock()
		requests, responses = nil, nil
		mu.Unlock()
		for attempt := range 4 {
			result, err := prepare(request)
			if attempt < 3 {
				if err == nil {
					t.Fatal("lost committed reply unexpectedly reached the client")
				}
			} else {
				if err != nil {
					t.Fatal("exact retry could not recover the committed pair", err)
				}
				if action == "replace" && (result.PairId == pair.PairId || result.Key == pair.Key || result.DeliveryGeneration <= pair.DeliveryGeneration) {
					t.Fatal("replacement did not rotate the exact owner's delivery")
				}
				pair = result
			}
			var owners int
			if err := conn.QueryRow(ctx, `SELECT count(*) FROM control.connector_peer_pairs WHERE service_run_id=$1 AND owner_key=$2`, request.ServiceRunId, request.IdempotencyKey).Scan(&owners); err != nil || owners != 1 {
				t.Fatal("ambiguous retry allocated another owner", owners, err)
			}
		}
		mu.Lock()
		bodies := append([][]byte(nil), requests...)
		replies := append([][]byte(nil), responses...)
		mu.Unlock()
		if len(bodies) != 4 || len(replies) != 4 {
			t.Fatal("response-loss fixture did not exercise all four committed attempts")
		}
		for index := range bodies {
			if !bytes.Equal(bodies[0], bodies[index]) {
				t.Fatal("retry changed the signed request or owner key")
			}
			var delivered controlv1.ConnectorPeerPair
			if err := json.Unmarshal(replies[index], &delivered); err != nil || delivered.ObservedAt.IsZero() || delivered.ObservedAt.After(pair.ObservedAt) {
				t.Fatal("invalid committed reply", err)
			}
			delivered.ObservedAt = pair.ObservedAt
			if !reflect.DeepEqual(delivered, pair) {
				t.Fatal("retry changed the committed key, binding, or original expiry")
			}
		}
		var ciphertext []byte
		if err := conn.QueryRow(ctx, `SELECT key_ciphertext FROM control.connector_peer_pairs WHERE id=$1`, pair.PairId).Scan(&ciphertext); err != nil {
			t.Fatal(err)
		}
		key, err := base64.RawURLEncoding.Strict().DecodeString(pair.Key)
		if err != nil || len(key) != 32 || bytes.Contains(ciphertext, key) || bytes.Contains(ciphertext, []byte(pair.Key)) {
			t.Fatal("committed delivery key was not encrypted", err)
		}
	}
	// a new signed create is a permanent conflict, not ambiguous response loss.
	changed := request
	changed.Action, changed.PreviousPairId, changed.PreviousGeneration = "create", nil, nil
	changed.RequestedAt = time.Now().UTC().Truncate(time.Microsecond)
	message, err := controlv1.ConnectorPeerPairProofMessage(service, changed)
	if err != nil {
		t.Fatal(err)
	}
	changed.Signature = base64.RawURLEncoding.EncodeToString(sign(message))
	if _, err := prepare(changed); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("new create reused a committed owner after replacement", err)
	}
}
