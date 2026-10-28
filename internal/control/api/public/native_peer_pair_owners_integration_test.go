package public

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func assertNativeHTTPStableOwners(t *testing.T, d *controlstate.Database, conn *pgx.Conn, server *httptest.Server, bearer, service, runToken string, template controlv1.NativePeerPairRequest, sign func([]byte) []byte) {
	t.Helper()
	ctx := t.Context()
	call := func(body controlv1.NativePeerPairRequest) (int, []byte) {
		t.Helper()
		if body.IdempotencyKey != "" {
			message, err := controlv1.NativePeerPairProofMessage(service, body)
			if err != nil {
				t.Fatal(err)
			}
			body.Signature = base64.RawURLEncoding.EncodeToString(sign(message))
		}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/services/"+service+"/native-peer-pairs", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("invalid HTTP consumer response", err)
		}
		return response.StatusCode, data
	}
	var pairs [2]controlv1.NativePeerPair
	ids := []string{}
	defer func() {
		if _, err := conn.Exec(ctx, `DELETE FROM control.native_peer_pairs WHERE id=ANY($1::text[])`, ids); err != nil {
			t.Error(err)
		}
	}()
	for i, owner := range []string{"http-regression-owner-a", "http-regression-owner-b"} {
		r := template
		r.IdempotencyKey = owner
		code, data := call(r)
		var pair controlv1.NativePeerPair
		if code != 200 || json.Unmarshal(data, &pair) != nil || pair.Key == "" {
			t.Fatal("valid HTTP independent owner was not created", code)
		}
		pairs[i] = pair
		ids = append(ids, pair.PairId)
		at := time.Now().UTC().Truncate(time.Microsecond)
		for slot, relay := range pair.Relays {
			proof := tunnelv1.NativePairLegProof{PairID: pair.PairId, DeliveryGeneration: pair.DeliveryGeneration, ServiceID: service, ServiceRunID: pair.ServiceRunId, RunNumber: pair.RunNumber, PublisherIdentityID: pair.PublisherIdentityId, ConnectionSlot: slot,
				PublisherConnectionID: relay.PublisherConnectionId, AssignmentRevision: relay.AssignmentRevision, RelayServiceID: relay.RelayLease.RelayServiceId, RelayID: relay.RelayLease.RelayId, RelayRunID: relay.RelayLease.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLease.RelayLeaseRevision), RequestedAt: at, Nonce: bytes.Repeat([]byte{byte(slot + 1)}, 32)}
			message, err := proof.Message()
			if err != nil {
				t.Fatal(err)
			}
			proof.Signature = sign(message)
			source := netip.MustParseAddr("192.0.2.10")
			message, err = proof.RelayClaimMessage(source)
			if err != nil {
				t.Fatal(err)
			}
			seed := sha256.Sum256([]byte(proof.RelayRunID))
			lease := controlstate.RelayLeaseIdentity{RelayServiceID: proof.RelayServiceID, RelayID: proof.RelayID, RelayRunID: proof.RelayRunID, RelayLeaseRevision: proof.RelayLeaseRevision}
			if _, err := d.ClaimNativePeerPairLeg(ctx, lease, source, proof, ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), message), at); err != nil {
				t.Fatal("valid HTTP owner relay claim", err)
			}
		}
		at = time.Now().UTC().Truncate(time.Microsecond)
		delivery, err := d.DeliverNativePeerPair(ctx, service, pair.ServiceRunId, pair.PairId, pair.DeliveryGeneration, runToken, at)
		if err != nil {
			t.Fatal("valid HTTP owner delivery", err)
		}
		if err := d.ConfirmNativePeerPairPrepared(ctx, service, pair.ServiceRunId, pair.PairId, runToken, controlstate.NativePeerPairPrepared{DeliveryID: delivery.DeliveryID, DeliveryGeneration: pair.DeliveryGeneration, BindingExpiresAt: delivery.ExpiresAt}, at); err != nil {
			t.Fatal("valid HTTP owner report", err)
		}
	}
	if pairs[0].PairId == pairs[1].PairId || pairs[0].Key == pairs[1].Key {
		t.Fatal("HTTP fixture shared independent owner material")
	}
	snapshot := func() []byte {
		t.Helper()
		var saved []byte
		if err := conn.QueryRow(ctx, `SELECT jsonb_build_object(
		'pairs',(SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY p.id),'[]') FROM control.native_peer_pairs p WHERE id=ANY($1::text[])),
		'claims',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY c.pair_id,c.connection_slot),'[]') FROM control.native_peer_pair_leg_claims c WHERE pair_id=ANY($1::text[])))::text`, ids).Scan(&saved); err != nil {
			t.Fatal(err)
		}
		var facts []byte
		if err := conn.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_object(
		'pair_id',p.id,'generation',p.delivery_generation,'expires_at',p.expires_at,'report_until',p.publisher_prepared_until,
		'claims',(SELECT COALESCE(jsonb_agg(jsonb_build_object('slot',c.connection_slot,'checked_at',c.checked_at,'confirmed_until',c.confirmed_until) ORDER BY c.connection_slot),'[]') FROM control.native_peer_pair_leg_claims c WHERE c.pair_id=p.id)) ORDER BY p.id),'[]')::text FROM control.native_peer_pairs p WHERE p.id=ANY($1::text[])`, ids).Scan(&facts); err != nil {
			t.Fatal(err)
		}
		t.Logf("saved HTTP owner facts (no keys): %s", facts)
		return saved
	}
	for _, key := range []string{"http-regression-owner-b", "http-fresh-unused-owner-c", ""} {
		before := snapshot()
		crossed := template
		crossed.Action, crossed.IdempotencyKey = "replace", key
		crossed.PreviousPairId, crossed.PreviousGeneration = &pairs[0].PairId, &pairs[0].DeliveryGeneration
		crossed.RequestedAt = time.Now().UTC().Truncate(time.Microsecond)
		code, data := call(crossed)
		var successor controlv1.NativePeerPair
		if code == 200 && json.Unmarshal(data, &successor) == nil {
			ids = append(ids, successor.PairId)
		}
		after := snapshot()
		var aExists, bExists, adopted bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.native_peer_pairs WHERE id=$1),EXISTS(SELECT 1 FROM control.native_peer_pairs WHERE id=$2),EXISTS(SELECT 1 FROM control.native_peer_pairs WHERE id=$3 AND owner_key=$4)`, pairs[0].PairId, pairs[1].PairId, successor.PairId, "http-regression-owner-a").Scan(&aExists, &bExists, &adopted); err != nil {
			t.Fatal(err)
		}
		t.Logf("HTTP subject=%s unused_key=%t status=%d before_sha256=%x after_sha256=%x a_retained=%t b_retained=%t adopted_a_owner=%t", template.Subject.Kind, key != "http-regression-owner-b", code, sha256.Sum256(before), sha256.Sum256(after), aExists, bExists, adopted)
		want := http.StatusConflict
		if key == "" {
			want = http.StatusBadRequest
		}
		if code != want || !bytes.Equal(before, after) || !aExists || !bExists || adopted {
			t.Fatal("HTTP cross-owner replacement changed rows/claims/report/expiry or adopted owner")
		}
	}
}
