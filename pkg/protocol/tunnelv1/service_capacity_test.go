package tunnelv1

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestServiceCapacityRequestBindsTheWholeStream(t *testing.T) {
	header := publicServiceAdmissionFixture()
	request := ServiceCapacityRequest{Kind: "service_capacity", Stream: header, Deadline: time.Now().Add(time.Second)}
	var wire bytes.Buffer
	if err := WriteServiceCapacityRequest(&wire, request); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadServiceCapacityRequest(&wire)
	if err != nil || !SameServiceStream(decoded.Stream, header) || !decoded.Deadline.Equal(request.Deadline) {
		t.Fatal("capacity request changed its stream or deadline", err)
	}
	changes := map[string]func(*ServiceForwardingHeader){
		"service":        func(h *ServiceForwardingHeader) { h.ServiceID += "x" },
		"run":            func(h *ServiceForwardingHeader) { h.ServiceRunID += "x" },
		"number":         func(h *ServiceForwardingHeader) { h.RunNumber++ },
		"visitor":        func(h *ServiceForwardingHeader) { h.VisitorConnectionID += "x" },
		"publisher":      func(h *ServiceForwardingHeader) { h.PublisherConnectionID += "x" },
		"slot":           func(h *ServiceForwardingHeader) { h.ConnectionSlot = 1 },
		"assignment":     func(h *ServiceForwardingHeader) { h.ConnectionAssignmentRevision++ },
		"relay":          func(h *ServiceForwardingHeader) { h.RelayID += "x" },
		"relay-run":      func(h *ServiceForwardingHeader) { h.RelayRunID += "x" },
		"relay-lease":    func(h *ServiceForwardingHeader) { h.RelayLeaseRevision++ },
		"source":         func(h *ServiceForwardingHeader) { h.SourceIP = "192.0.2.11" },
		"ingress":        func(h *ServiceForwardingHeader) { h.PublicService.IngressID += "x" },
		"ingress-run":    func(h *ServiceForwardingHeader) { h.PublicService.IngressRunID += "x" },
		"ingress-lease":  func(h *ServiceForwardingHeader) { h.PublicService.IngressLeaseRevision++ },
		"port":           func(h *ServiceForwardingHeader) { h.PublicService.DestinationPort++ },
		"expiry":         func(h *ServiceForwardingHeader) { h.ExpiresAt = h.ExpiresAt.Add(time.Second) },
		"serving-expiry": func(h *ServiceForwardingHeader) { h.ServingUntil = h.ServingUntil.Add(time.Second) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			other := header
			admission := *header.PublicService
			other.PublicService = &admission
			change(&other)
			if SameServiceStream(header, other) {
				t.Fatal("capacity request accepted a different stream")
			}
		})
	}
}

func TestServiceCapacityRequestRejectsInvalidWire(t *testing.T) {
	header := publicServiceAdmissionFixture()
	request := ServiceCapacityRequest{Kind: "service_capacity", Stream: header, Deadline: time.Now().Add(time.Second)}
	for _, change := range []func(*ServiceCapacityRequest){
		func(r *ServiceCapacityRequest) { r.Kind = "service_forward" },
		func(r *ServiceCapacityRequest) { r.Deadline = time.Time{} },
		func(r *ServiceCapacityRequest) { r.Deadline = r.Stream.ExpiresAt.Add(time.Second) },
		func(r *ServiceCapacityRequest) { r.Stream.ServiceID = "" },
	} {
		other := request
		change(&other)
		if WriteServiceCapacityRequest(new(bytes.Buffer), other) == nil {
			t.Fatal("invalid request was written")
		}
		body, err := json.Marshal(other)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ReadServiceCapacityRequest(frame(string(body))); err == nil {
			t.Fatal("invalid request was accepted")
		}
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.TrimSuffix(string(body), "}") + `,"credential":"not-authority"}`
	if _, err := ReadServiceCapacityRequest(frame(unknown)); err == nil {
		t.Fatal("capacity request accepted a visitor credential field")
	}
	if _, err := ReadServiceCapacityRequest(frame(strings.Repeat("x", MaxServiceHeaderBytes+1))); err == nil {
		t.Fatal("capacity request accepted an oversized request")
	}
}
