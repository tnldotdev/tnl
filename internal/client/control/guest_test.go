package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/httpjson"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestGuestBootstrapUsesOrdinaryServiceAndEnrollment(t *testing.T) {
	until := time.Now().UTC().Add(time.Hour)
	service := controlv1.Service{Id: "svc_1111111111111111111111", GuestId: "gst_1111111111111111111111",
		Protocol: controlv1.ServiceProtocolHTTP, Enabled: true, Ephemeral: true, ExpiresAt: &until}
	enrollment := authorityv1.PublisherEnrollmentResult{ClientId: "pid_1111111111111111111111",
		KeyId: "pk_1111111111111111111111", GrantId: "pg_1111111111111111111111",
		GuestId: service.GuestId, Kind: authorityv1.Service, ServiceId: &service.Id, ExpiresAt: &until}
	public := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer trial-token" {
			t.Error("guest bootstrap lost its distinct trial credential")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/guest-demo/services":
			var body controlv1.AllocateGuestDemoServiceRequest
			if err := httpjson.Decode(json.NewDecoder(r.Body), &body); err != nil ||
				body.Target != "http://127.0.0.1:43127" || body.RequirePostQuantum == nil || !*body.RequirePostQuantum ||
				r.Header.Get("Idempotency-Key") != "original-intent" {
				t.Error("guest allocation changed its original bounded intent")
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(service)
		case "/v1/guest-demo/publisher":
			var body controlv1.EnrollGuestPublisherRequest
			if err := httpjson.Decode(json.NewDecoder(r.Body), &body); err != nil ||
				body.ServiceId != service.Id || body.PublicKey != base64.RawURLEncoding.EncodeToString(public) {
				t.Error("guest enrollment changed its exact service or signing key")
			}
			_ = json.NewEncoder(w).Encode(enrollment)
		default:
			t.Error("guest bootstrap used an obsolete resource family")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "trial-token")
	if err != nil {
		t.Fatal(err)
	}
	saved, err := client.AllocateGuestDemoService(t.Context(), "original-intent",
		controlv1.AllocateGuestDemoServiceRequest{Target: "http://127.0.0.1:43127", RequirePostQuantum: new(true)})
	if err != nil || saved.Id != service.Id || saved.GuestId != service.GuestId || saved.TeamId != "" ||
		saved.ExpiresAt == nil || !saved.ExpiresAt.Equal(until) {
		t.Fatal("guest bootstrap did not return the ordinary fixed-lifetime service", err)
	}
	receipt, err := client.EnrollGuestPublisher(t.Context(), saved.Id, public)
	if err != nil || receipt.ServiceId == nil || *receipt.ServiceId != service.Id ||
		receipt.GuestId != service.GuestId || receipt.TeamId != "" || receipt.Kind != authorityv1.Service ||
		receipt.ExpiresAt == nil || !receipt.ExpiresAt.Equal(until) || requests.Load() != 2 {
		t.Fatal("guest enrollment did not preserve the defining ordinary receipt", err)
	}
}
