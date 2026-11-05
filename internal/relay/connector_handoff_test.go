package relay

import (
	"encoding/binary"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestHandoffRecordsAdvanceAndExactRetryBeforeInstallation(t *testing.T) {
	at := time.Now()
	initial := tunnelv1.InitialConnectorActivation(tunnelv1.ConnectorHelloNonce{1})
	s := initialHandoff(initial, at)
	op, err := tunnelv1.NewConnectorHandoff(initial.SelectedHandoff(), tunnelv1.ConnectorHandoffID{2}, 1)
	if err != nil {
		t.Fatal(err)
	}
	selection := tunnelv1.InitialConnectorActivation(tunnelv1.ConnectorHelloNonce{3}).Replacing(op)
	if got := s.record(selection, at.Add(time.Microsecond)); got != handoffAdvanced {
		t.Fatal("first operation did not advance", got)
	}
	if got := s.record(selection, at.Add(time.Microsecond)); got != handoffRejected {
		t.Fatal("same hello timestamp was replayed", got)
	}
	if got := s.record(selection, at.Add(2*time.Microsecond)); got != handoffRejected {
		t.Fatal("same hello nonce was reused with a newer timestamp", got)
	}
	fresh := tunnelv1.InitialConnectorActivation(tunnelv1.ConnectorHelloNonce{4}).Replacing(op)
	if got := s.record(fresh, at.Add(2*time.Microsecond)); got != handoffRetried || s.operation.Revision() != 1 {
		t.Fatal("exact operation retry consumed history", got)
	}
	if got := s.record(initial, at.Add(3*time.Microsecond)); got != handoffRejected {
		t.Fatal("initial activation reset history", got)
	}
}

func TestHandoffRetainsOnlyFixedSizeStateWithoutPerOperationAllocation(t *testing.T) {
	// time.Time is a fixed-size value; no identity history can hide in a map,
	// slice, pointer, or interface owned by the handoff state.
	var fixed func(reflect.Type) bool
	fixed = func(typ reflect.Type) bool {
		if typ == reflect.TypeFor[time.Time]() {
			return true
		}
		switch typ.Kind() {
		case reflect.Struct:
			for i := range typ.NumField() {
				if !fixed(typ.Field(i).Type) {
					return false
				}
			}
		case reflect.Array:
			return fixed(typ.Elem())
		case reflect.Map, reflect.Slice, reflect.Pointer, reflect.Interface, reflect.String:
			return false
		}
		return true
	}
	if !fixed(reflect.TypeFor[handoffState]()) {
		t.Fatal("handoff state owns growing storage")
	}
	at := time.Now()
	s := initialHandoff(tunnelv1.InitialConnectorActivation(tunnelv1.ConnectorHelloNonce{1}), at)
	var counter uint64
	allocations := testing.AllocsPerRun(1024, func() {
		counter++
		var id tunnelv1.ConnectorHandoffID
		var hello tunnelv1.ConnectorHelloNonce
		binary.BigEndian.PutUint64(id[24:], counter)
		binary.BigEndian.PutUint64(hello[24:], counter)
		op, err := tunnelv1.NewConnectorHandoff(s.selected, id, tunnelv1.ConnectorHandoffRevision(counter))
		if err != nil || s.record(tunnelv1.InitialConnectorActivation(hello).Replacing(op), at.Add(time.Duration(counter)*time.Microsecond)) != handoffAdvanced {
			panic("valid handoff failed")
		}
	})
	if allocations != 0 || s.operation.Revision() <= 64 {
		t.Fatal("handoffs allocated identity history or stopped early", allocations, s.operation.Revision())
	}
}
