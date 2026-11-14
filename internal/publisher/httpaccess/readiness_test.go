package httpaccess

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
)

func readinessTestRun() ReadinessRun {
	return ReadinessRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("S", 22)},
		ID: "srun_" + strings.Repeat("R", 22), Number: 7, Hostname: "web.example.test"}
}

func TestReadinessProofFencesEveryRunAndRequestFact(t *testing.T) {
	run := readinessTestRun()
	for _, boundary := range []string{"resource", "run", "number", "hostname", "method", "path", "query", "body", "chunked", "upgrade", "duplicate", "secret"} {
		t.Run(boundary, func(t *testing.T) {
			proof, err := NewReadinessProof(run, "/health")
			if err != nil {
				t.Fatal(err)
			}
			other := run
			r := httptest.NewRequest(http.MethodGet, "/health", nil)
			r.Header.Set(publisherproxy.ReadinessProbeHeader, proof.HeaderValue())
			switch boundary {
			case "resource":
				other.Subject.ID = "svc_" + strings.Repeat("T", 22)
			case "run":
				other.ID = "srun_" + strings.Repeat("T", 22)
			case "number":
				other.Number++
			case "hostname":
				other.Hostname = "other.example.test"
			case "method":
				r.Method = http.MethodPost
			case "path":
				r.URL.Path = "/other"
			case "query":
				r.URL.RawQuery = "private=query"
			case "body":
				r.ContentLength = 1
			case "chunked":
				r.ContentLength, r.TransferEncoding = -1, []string{"chunked"}
			case "upgrade":
				r.Header.Set("Upgrade", "websocket")
			case "duplicate":
				r.Header.Add(publisherproxy.ReadinessProbeHeader, proof.HeaderValue())
			case "secret":
				r.Header.Set(publisherproxy.ReadinessProbeHeader, "wrong")
			}
			if proof.Consume(r, other) {
				t.Fatal("proof crossed", boundary)
			}
			valid := httptest.NewRequest(http.MethodGet, "/health", nil)
			valid.Header.Set(publisherproxy.ReadinessProbeHeader, proof.HeaderValue())
			if !proof.Consume(valid, run) || proof.Consume(valid, run) || proof.HeaderValue() != "" {
				t.Fatal("rejection spent the proof or valid use was not single-use")
			}
		})
	}
}

func TestReadinessProofExpiresAtDeadlineAndRenewalReplacesSecret(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		run := readinessTestRun()
		proof, err := NewReadinessProof(run, "/health")
		if err != nil {
			t.Fatal(err)
		}
		old := proof.HeaderValue()
		next, err := proof.Renew()
		if err != nil || old == next || len(next) != 64 {
			t.Fatal("renewal did not replace the secret", err)
		}
		request := httptest.NewRequest(http.MethodGet, "/health", nil)
		request.Header.Set(publisherproxy.ReadinessProbeHeader, old)
		if proof.Consume(request, run) {
			t.Fatal("renewal retained an earlier secret")
		}
		time.Sleep(2 * time.Minute)
		request.Header.Set(publisherproxy.ReadinessProbeHeader, next)
		if proof.Consume(request, run) {
			t.Fatal("proof was usable at its deadline")
		}
		next, err = proof.Renew()
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(publisherproxy.ReadinessProbeHeader, next)
		if !proof.Consume(request, run) {
			t.Fatal("a fresh proof could not be used after expiry")
		}
	})
}

func TestReadinessProofConcurrentUseHasOneWinner(t *testing.T) {
	run := readinessTestRun()
	proof, err := NewReadinessProof(run, "/health")
	if err != nil {
		t.Fatal(err)
	}
	secret := proof.HeaderValue()
	var workers sync.WaitGroup
	var accepted atomic.Int32
	for range 16 {
		workers.Go(func() {
			r := httptest.NewRequest(http.MethodGet, "/health", nil)
			r.Header.Set(publisherproxy.ReadinessProbeHeader, secret)
			if proof.Consume(r, run) {
				accepted.Add(1)
			}
		})
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatal("proof was not consumed atomically", accepted.Load())
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, proof), secret) {
			t.Fatal("proof formatting disclosed a secret")
		}
	}
}

func TestReadinessProofRejectsUnscopedOrReservedPaths(t *testing.T) {
	run := readinessTestRun()
	for _, path := range []string{"", "health", "/health?x=1", "/health#fragment", "/health\r\n", "/__tnl/health"} {
		if _, err := NewReadinessProof(run, path); err == nil {
			t.Fatal("invalid probe path accepted", path)
		}
	}
	run.Subject = visitorscope.Scope{}
	if _, err := NewReadinessProof(run, "/health"); err == nil {
		t.Fatal("proof had no resource authority")
	}
}
