package service

import (
	"bytes"
	"errors"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func publicSourceMetadata(t *testing.T, prepared *Prepared, header tunnelv1.ServiceForwardingHeader) []byte {
	t.Helper()
	view, enabled, _ := prepared.policy.Current()
	if !enabled {
		t.Fatal("source fixture needs current serving policy")
	}
	now := view.AuthorityTime(time.Now())
	prepared.sourceKey = [32]byte{1}
	authority, key, err := visitortoken.IssueVisitorSourceAuthority(prepared.sourceKey, tunnelv1.VisitorSourceAuthority{
		ServiceID: header.ServiceID, ServiceRunID: header.ServiceRunID, RunNumber: header.RunNumber, EndpointRevision: 1,
		IngressID: header.PublicService.IngressID, IngressRunID: header.PublicService.IngressRunID,
		IngressLeaseRevision: header.PublicService.IngressLeaseRevision, VisitorPolicyRevision: view.VisitorPolicyRevision,
		ValidUntil: now.Add(visitortoken.PolicyLifetime).Unix(),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	metadata := proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("203.0.113.1:443")}
	proof, err := visitortoken.SignVisitorSource(key, authority, 1, tunnelv1.VisitorSourceBinding{
		ServiceID: header.ServiceID, ServiceRunID: header.ServiceRunID, RunNumber: header.RunNumber,
		VisitorConnectionID: header.VisitorConnectionID, Source: metadata.Source, Destination: metadata.Destination,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	metadata.VisitorSourceProof = string(wire)
	encoded, err := proxyproto.Encode(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestVisitorSourceReplayWindowPreservesEveryReorderAndRejectsOldSequences(t *testing.T) {
	for _, shift := range []uint64{1, 63, 64, 65, 127, 128, 191, 192, 255, 256, 257, 1024} {
		var window sourceProofWindow
		if err := window.remember(256); err != nil {
			t.Fatal(err)
		}
		for sequence := uint64(1); sequence < 256; sequence += 2 {
			if err := window.remember(sequence); err != nil {
				t.Fatal("reordered sequence rejected", shift, sequence, err)
			}
		}
		if err := window.remember(256 + shift); err != nil {
			t.Fatal(err)
		}
		for sequence := uint64(1); sequence < 256+shift; sequence++ {
			wantReplay := sequence <= shift || sequence == 256 || sequence < 256 && sequence%2 == 1
			err := window.remember(sequence)
			if errors.Is(err, errSourceProofReplay) != wantReplay || err != nil && !errors.Is(err, errSourceProofReplay) {
				t.Fatal("window lost used evidence or bounded reordering", shift, sequence, err)
			}
		}
		if err := window.remember(0); !errors.Is(err, errSourceProofReplay) {
			t.Fatal("zero sequence was remembered", err)
		}
	}
}

func TestVisitorSourceReplayWindowAtSequenceLimit(t *testing.T) {
	var window sourceProofWindow
	for _, sequence := range []uint64{math.MaxUint64 - 255, math.MaxUint64 - 1, math.MaxUint64} {
		if err := window.remember(sequence); err != nil {
			t.Fatal("window could not reach the last sequence number", sequence, err)
		}
	}
	for _, sequence := range []uint64{math.MaxUint64 - 256, math.MaxUint64 - 255, math.MaxUint64 - 1, math.MaxUint64, 0, 1} {
		if err := window.remember(sequence); !errors.Is(err, errSourceProofReplay) {
			t.Fatal("sequence overflow or reuse cleared source history", sequence, err)
		}
	}
	if err := window.remember(math.MaxUint64 - 2); err != nil {
		t.Fatal("last-sequence handling rejected a valid reordered opening", err)
	}
}

func TestVisitorSourceReplayHasOneRunOwnerAndImmutableRetirement(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	proof := tunnelv1.VisitorSourceProof{
		Authority: tunnelv1.VisitorSourceAuthority{MAC: bytes.Repeat([]byte{1}, 32), ValidUntil: now.Add(10 * time.Second).Unix()},
		Sequence:  1,
	}
	var history sourceProofHistory
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for range 100 {
		workers.Go(func() {
			if err := history.remember(proof, now); err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, errSourceProofReplay) {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if accepted.Load() != 1 || len(history.windows) != 1 || len(history.expirations) != 1 {
		t.Fatal("concurrent relay paths remembered one proof more than once", accepted.Load())
	}
	until := proof.Authority.ValidUntil
	renewed := proof
	renewed.Authority.MAC = bytes.Repeat([]byte{2}, 32)
	renewed.Authority.ValidUntil = until + 10
	if err := history.remember(renewed, time.Unix(until-1, 0)); err != nil {
		t.Fatal(err)
	}
	if len(history.windows) != 2 {
		t.Fatal("new authority removed still-current history")
	}
	if err := history.remember(proof, time.Unix(until-1, 0)); !errors.Is(err, errSourceProofReplay) {
		t.Fatal("renewal cleared an old replay check", err)
	}
	renewed.Sequence++
	if err := history.remember(renewed, time.Unix(until, 0)); err != nil || len(history.windows) != 1 {
		t.Fatal("expired evidence was not removed at its original deadline", err)
	}
	for _, at := range []time.Time{time.Unix(until, 0), time.Unix(until-1, 0), time.Unix(until, 0).Add(-time.Hour)} {
		if err := history.remember(proof, at); !errors.Is(err, visitortoken.ErrVisitorSource) {
			t.Fatal("clock rollback made expired evidence usable again", err)
		}
	}
}
