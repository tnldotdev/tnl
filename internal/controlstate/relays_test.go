package controlstate

import (
	"errors"
	"math"
	"net/netip"
	"testing"
	"time"
)

func TestRelayRegistrationValidation(t *testing.T) {
	t.Parallel()
	valid := RelayRegistration{
		RelayServiceID: "relay_service_a", RelayID: "relay_a", RelayRunID: "run_a", ProtocolVersion: 1,
		RelayAddress: "relay.example:443", TLSServerName: "relay.example",
		InternalRelayAddress: "relay.internal:9443",
		InternalNetworks:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		ConnectionCapacity:   10, StreamCapacity: 100,
	}
	if err := validateRelayRegistration(valid, time.Minute); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*RelayRegistration){
		"empty relay ID":        func(value *RelayRegistration) { value.RelayID = "" },
		"whitespace service ID": func(value *RelayRegistration) { value.RelayServiceID = " relay_service_a" },
		"zero protocol":         func(value *RelayRegistration) { value.ProtocolVersion = 0 },
		"large protocol":        func(value *RelayRegistration) { value.ProtocolVersion = math.MaxUint64 },
		"zero connections":      func(value *RelayRegistration) { value.ConnectionCapacity = 0 },
		"zero streams":          func(value *RelayRegistration) { value.StreamCapacity = 0 },
		"host bits": func(value *RelayRegistration) {
			value.InternalNetworks = []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}
		},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := valid
			mutate(&invalid)
			if err := validateRelayRegistration(invalid, time.Minute); err == nil {
				t.Fatal("validation succeeded")
			}
		})
	}
	if err := validateRelayRegistration(valid, 0); err == nil {
		t.Fatal("zero lease duration succeeded")
	}
}

func TestRelayStateMethodsRequireOpenDatabase(t *testing.T) {
	t.Parallel()
	registration := RelayRegistration{
		RelayServiceID: "relay_service_a", RelayID: "relay_a", RelayRunID: "run_a", ProtocolVersion: 1,
		RelayAddress: "relay.example:443", TLSServerName: "relay.example",
		InternalRelayAddress: "relay.internal:9443", ConnectionCapacity: 10, StreamCapacity: 100,
	}
	identity := RelayLeaseIdentity{
		RelayServiceID: "relay_service_a", RelayID: "relay_a", RelayRunID: "run_a", RelayLeaseRevision: 1,
	}
	var database *Database
	if _, err := database.RegisterRelay(t.Context(), registration, time.Now(), time.Minute); err == nil {
		t.Fatal("RegisterRelay succeeded")
	}
	if _, err := database.RenewRelay(t.Context(), RelayRenewal{
		RelayLeaseIdentity: identity,
	}, time.Now(), time.Minute); err == nil {
		t.Fatal("RenewRelay succeeded")
	}
	if _, err := database.BeginRelayDrain(
		t.Context(), identity, time.Now(), time.Now().Add(time.Minute),
	); err == nil {
		t.Fatal("BeginRelayDrain succeeded")
	}
}

func TestRelayStateErrorsAreDistinct(t *testing.T) {
	t.Parallel()
	values := []error{
		ErrRelayRegistrationConflict, ErrRelayLeaseStale, ErrRelayDraining, ErrRelayConnectionCapacity,
		ErrPublisherConnectionUnavailable, ErrPublisherConnectionCredential, ErrConnectionAssignmentStale,
		ErrPublisherConnectionAlreadyClaimed, ErrPublisherConnectionRelayService,
	}
	for index, left := range values {
		for otherIndex, right := range values {
			if index != otherIndex && errors.Is(left, right) {
				t.Fatalf("%v matches %v", left, right)
			}
		}
	}
}
