package tunnelv1

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPeerConnectorRenewalKeepsEveryLegBindingField(t *testing.T) {
	hello, err := ReadControl(bytes.NewReader(goldenWire(t, "control-connector-hello")))
	if err != nil {
		t.Fatal(err)
	}
	proof := *hello.ConnectorPairLegProof
	fresh := proof
	fresh.RequestedAt = fresh.RequestedAt.Add(time.Second)
	fresh.Nonce, fresh.Signature = bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 64)
	if !proof.SameLeg(fresh) {
		t.Fatal("fresh proof changed an immutable leg binding")
	}
	fields := reflect.TypeFor[ConnectorPairLegProof]()
	for index := range fields.NumField() {
		name := fields.Field(index).Name
		if name == "RequestedAt" || name == "Nonce" || name == "Signature" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			changed := proof
			value := reflect.ValueOf(&changed).Elem().Field(index)
			switch value.Kind() {
			case reflect.String:
				value.SetString(value.String() + "x")
			case reflect.Int, reflect.Int64:
				value.SetInt(value.Int() + 1)
			case reflect.Uint64:
				value.SetUint(value.Uint() + 1)
			default:
				t.Fatal("new binding field needs a substitution test")
			}
			if proof.SameLeg(changed) {
				t.Fatal("renewal accepted a substituted leg field")
			}
		})
	}
}

func TestPeerConnectorRenewalClosedWireShapes(t *testing.T) {
	request := string(readFixture(t, "control-connector-renew.json"))
	response := string(readFixture(t, "control-connector-renewed.json"))
	for _, bad := range []string{
		strings.Replace(request, `"request_id": "renew_1",`, "", 1),
		strings.Replace(request, `"role": "connector",`, `"role":"publisher",`, 1),
		strings.Replace(request, `"role": "connector",`, `"role":"connector","credential":null,`, 1),
		strings.Replace(response, `"request_id": "renew_1",`, "", 1),
		strings.Replace(response, `"request_id": "renew_1",`, `"request_id":"renew_1","connector_pair_leg_proof":null,`, 1),
		`{"type":"connector_leg_renewed","protocol_version":1,"request_id":"renew_1","connector_pair_leg_accepted":null}`,
	} {
		if err := readControl(frame(bad)); err == nil {
			t.Fatal("accepted invalid connector renewal fields")
		}
	}
}
