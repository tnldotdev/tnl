package daemon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publicLoadPreparation struct {
	URL, Entry string
	Transport  string
}

type publicLoadPhase struct {
	Name                              string
	Start                             time.Time
	Duration                          time.Duration
	Direct, HTTP2, Reuse, Probe, Done bool
}

func runSeparatedPublicAuthorization(t *testing.T, database *sql.DB, publishers separatedPublishers, rate int, duration time.Duration) {
	state, err := controlstate.Open(t.Context(), testutil.PostgresURL(t), testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	session, err := controltest.Session(t.Context(), state, "routes."+separatedDomain, time.Hour, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, client := connectLoadClient(t, t.Context())
	for visitor := 1; visitor <= 4; visitor++ {
		var preparations []publicLoadPreparation
		for index := visitor - 1; index < len(publishers.URLs); index += 4 {
			ready := publishers.Ready[index]
			preparation := publicLoadPreparation{URL: publishers.URLs[index], Transport: "quic"}
			if index%2 != 0 {
				preparation.Transport = "tls-tcp"
			}
			switch *publicLoadAccess {
			case "browser":
				handoff, err := state.IssueBrowserHandoff(t.Context(), controlstate.BrowserLoginAttempt{PublicURLID: ready.PublicURLID, ReturnPath: "/bench"},
					controlstate.BrowserAccessSession{ParentControlSessionID: session.SessionID, IdentityID: session.Identity.Identity.ID, DisplayName: session.Identity.Identity.DisplayName,
						AccessToken: session.AccessToken.String(), RefreshToken: session.RefreshToken.String(), AccessExpiresAt: session.AccessExpiresAt, ExpiresAt: session.RefreshExpiresAt}, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				preparation.Entry = handoff.Origin + "/__tnl/team/handoff/" + handoff.Token
			case "share":
				secret := make([]byte, 32)
				if _, err := rand.Read(secret); err != nil {
					t.Fatal(err)
				}
				fingerprint := sha256.Sum256(secret)
				share, err := client.Control.CreateURLShare(t.Context(), fmt.Sprintf("visitor-load-%d", index), controlv1.CreateShareRequest{PublicUrlIds: []string{ready.PublicURLID}, ExpiresAt: time.Now().Add(time.Hour), SecretFingerprint: hex.EncodeToString(fingerprint[:])})
				if err != nil {
					t.Fatal(err)
				}
				preparation.Entry = preparation.URL + "/__tnl/share/" + share.Id + "." + base64.RawURLEncoding.EncodeToString(secret)
			}
			preparations = append(preparations, preparation)
		}
		// credentials cross only the private authenticated coordinator, never the
		// results directory. the provider sign-in itself is fixture preparation.
		separatedWrite(t, fmt.Sprintf("public.visitor-%d.prepare", visitor), preparations)
	}
	for visitor := 1; visitor <= 4; visitor++ {
		separatedWait(t, fmt.Sprintf("public.visitor-%d.ready", visitor), 30*time.Second, nil)
	}
	var phases = []publicLoadPhase{
		{Name: "direct-fresh", Direct: true},
		{Name: "cold-fresh", Probe: true},
		{Name: "warm-fresh"},
		{Name: "warm-http2", HTTP2: true, Reuse: true},
		{Name: "refresh-due-fresh", Probe: true},
	}
	for sequence, phase := range phases {
		if phase.Name == "refresh-due-fresh" {
			// the old positive cache becomes refresh-due at 25 seconds. measure
			// the explicit wait separately from both offering and request latency.
			started := time.Now()
			if err := benchworkload.WaitUntil(t.Context(), started.Add(26*time.Second)); err != nil {
				t.Fatal(err)
			}
			separatedResult(t, "permission-refresh-wait", map[string]time.Duration{"elapsed": time.Since(started)})
		}
		before := separatedCapture(t, database, phase.Name+"-before")
		phase.Start, phase.Duration = time.Now().Add(time.Second), duration
		separatedWrite(t, fmt.Sprintf("public.phase-%d", sequence), phase)
		var results []connectLoadResult
		for visitor := 1; visitor <= 4; visitor++ {
			var result connectLoadResult
			separatedWait(t, fmt.Sprintf("%s.visitor-%d", phase.Name, visitor), duration+15*time.Second, &result)
			results = append(results, result)
		}
		after := separatedCapture(t, database, phase.Name+"-after")
		separatedReportResources(t, phase.Name, before, after)
		assertSeparatedNoMemoryLimitEvents(t, phase.Name, before, after)
		assertSeparatedNoRejections(t, phase.Name, before, after)
		expected := len(publishers.URLs)
		if !phase.Probe {
			expected = 0
			for visitor := range 4 {
				expected += int((time.Duration(benchworkload.Assignment(rate, 4, visitor))*duration + time.Second - 1) / time.Second)
			}
		}
		reportSetupLoad(t, phase.Name, results, expected)
		evidence := reportSeparatedSetupEvidence(t, phase.Name, phase.Start, time.Now())
		if !phase.Direct {
			if len(evidence.Visitors) == 0 {
				t.Error("no public visitor traces were captured")
			}
			for _, visitor := range evidence.Visitors {
				for operation, count := range visitor.ControlCalls {
					t.Errorf("public visitor made %d synchronous control calls for %s", count, operation)
				}
			}
		}
	}
	separatedWrite(t, fmt.Sprintf("public.phase-%d", len(phases)), publicLoadPhase{Done: true})
	separatedWrite(t, "close-half", time.Now())
	for shard := range separatedPublisherComponents() {
		separatedWait(t, separatedPublisherShardKey(shard, "close-half.done"), 30*time.Second, nil)
	}
	if runtimeEarlyFault(*runtimeLoadScenario) {
		separatedWrite(t, "fault.release", true)
		separatedWait(t, "fault.restored", 30*time.Second, nil)
	}
	verifySeparatedShutdown(t, database, len(publishers.URLs))
}

// prove both ingress processes can deliver a nonsecret, idempotent internal
// request before handing visitors one-use browser handoffs or share links.
// routing and allocation installation are background work, not proof from a
// ready publisher connection alone.
func waitSeparatedPublicVisitorTLS(t *testing.T, url string) {
	t.Helper()
	addresses := []string{"ingress-a-separated." + separatedDomain + ":443"}
	if *runtimeLoadHATopology {
		addresses = append(addresses, "ingress-b-separated."+separatedDomain+":443")
	}
	for _, address := range addresses {
		visitor := benchworkload.Visitor{Roots: separatedRoots(t, "route-roots.pem"), Address: address}
		client := visitor.OpenHTTP(false, false)
		deadline := time.Now().Add(15 * time.Second)
		status, failure := 0, ""
		for {
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url+"/__tnl/unknown", nil)
			if err != nil {
				t.Fatal("invalid prepared visitor probe")
			}
			response, err := client.Do(request)
			if err == nil {
				status = response.StatusCode
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
				_ = response.Body.Close()
				if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusSeeOther {
					break
				}
			} else {
				failure = fmt.Sprintf("%T", err)
			}
			if !time.Now().Before(deadline) {
				client.Close()
				t.Fatalf("prepared public visitor TLS did not become available; check ingress capacity and publisher policy (status=%d error_type=%s)", status, failure)
			}
			if err := benchworkload.WaitUntil(t.Context(), time.Now().Add(25*time.Millisecond)); err != nil {
				client.Close()
				t.Fatal("prepared public visitor probe was canceled")
			}
		}
		client.Close()
	}
}

func runSeparatedPublicAuthorizationVisitor(t *testing.T, ctx context.Context, component string, rate int) {
	var preparations []publicLoadPreparation
	if !separatedRead(t, ctx, "public."+component+".prepare", &preparations) {
		return
	}
	index, _ := strconv.Atoi(strings.TrimPrefix(component, "visitor-"))
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	visitor := benchworkload.Visitor{Roots: separatedRoots(t, "route-roots.pem"), Address: "ingress:443", PayloadBytes: 32768, Jar: jar}
	preparer := visitor.OpenHTTP(false, false)
	var urls []string
	cohorts := make(map[string]string)
	var setup benchworkload.Histogram
	for _, preparation := range preparations {
		urls = append(urls, preparation.URL)
		cohorts[preparation.URL] = preparation.Transport
		if preparation.Entry == "" {
			continue
		}
		waitSeparatedPublicVisitorTLS(t, preparation.URL)
		started := time.Now()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, preparation.Entry, nil)
		if err != nil {
			t.Fatal("invalid visitor preparation URL")
		}
		response, err := preparer.Do(request)
		if err != nil {
			t.Fatal("visitor preparation failed")
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		_ = response.Body.Close()
		setup.Observe(time.Since(started))
		parsed, _ := url.Parse(preparation.URL)
		if readErr != nil || response.StatusCode != http.StatusSeeOther || len(jar.Cookies(parsed)) == 0 {
			t.Fatalf("visitor preparation returned HTTP %d or no credential", response.StatusCode)
		}
		visitorPermission := false
		for _, cookie := range jar.Cookies(parsed) {
			visitorPermission = visitorPermission || cookie.Name == "__Host-tnl-visitor"
		}
		if !visitorPermission {
			t.Fatal("visitor handoff did not install its signed permission cookie")
		}
		check, err := http.NewRequestWithContext(ctx, http.MethodGet, preparation.URL+"/bench", nil)
		if err != nil {
			t.Fatal("invalid visitor preparation probe")
		}
		proof, err := preparer.Do(check)
		if err != nil {
			t.Fatalf("signed visitor cookie failed on its first request: %v", err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(proof.Body, 64<<10))
		_ = proof.Body.Close()
		if proof.StatusCode != http.StatusOK {
			t.Fatalf("signed visitor cookie was denied on its first request (status=%d)", proof.StatusCode)
		}
	}
	preparer.Close()
	separatedWrite(t, "public."+component+".ready", true)
	for sequence := 0; ; sequence++ {
		var phase publicLoadPhase
		if !separatedRead(t, ctx, fmt.Sprintf("public.phase-%d", sequence), &phase) {
			return
		}
		if phase.Done {
			break
		}
		phaseVisitor := visitor
		phaseURLs := urls
		if phase.Direct {
			phaseVisitor = benchworkload.Visitor{Roots: separatedRoots(t, "roots.pem"), Address: "publishers:8444", PayloadBytes: 32768}
			phaseURLs = []string{"https://direct." + separatedDomain}
		}
		client := phaseVisitor.OpenHTTP(phase.Reuse, phase.HTTP2)
		result := connectLoadResult{Setup: setup, Cohorts: make(map[string]benchworkload.VisitorResult)}
		setup = benchworkload.Histogram{}
		observe := func(row benchworkload.RequestResult) {
			result.Requests = append(result.Requests, row)
			cohort := result.Cohorts[cohorts[row.URL]]
			cohort.Scheduled++
			cohort.Observe(row)
			result.Cohorts[cohorts[row.URL]] = cohort
			if phase.HTTP2 && row.HTTPProtocol != "HTTP/2.0" {
				t.Error("HTTP/2 workload fell back to HTTP/1")
			}
		}
		if phase.Probe {
			for offset, address := range phaseURLs {
				scheduled := phase.Start.Add(time.Duration(offset) * time.Second)
				if err := benchworkload.WaitUntil(ctx, scheduled); err != nil {
					t.Error(err)
					break
				}
				row := client.Request(ctx, address, scheduled)
				observe(row)
				result.Summary.Scheduled++
				result.Summary.Observe(row)
			}
		} else {
			result.Summary, err = client.Run(ctx, benchworkload.VisitorConfig{Rate: benchworkload.Assignment(rate, 4, index-1), Workers: benchworkload.Assignment(*runtimeLoadWorkers, 4, index-1), QueueSlots: benchworkload.Assignment(*runtimeLoadQueue, 4, index-1), Start: phase.Start.Add(time.Duration(index-1) * time.Second / time.Duration(rate)), Duration: phase.Duration, OnResult: observe}, phaseURLs)
			if err != nil {
				t.Error(err)
			}
		}
		client.Close()
		separatedWrite(t, phase.Name+"."+component, result)
	}
	separatedWrite(t, component+".done", !t.Failed())
	<-ctx.Done()
}
