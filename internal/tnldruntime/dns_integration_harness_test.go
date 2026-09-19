package tnldruntime

import (
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/tnldotdev/tnl/internal/testutil"
)

var integrationDNSChild = flag.String("tnl-dns-child", "", "isolated DNS integration child test")

// Start a fresh process before net/http caches proxy settings. Even if the SDK
// ignores the endpoint override, its public API requests hit a rejecting proxy.
// Process-group cleanup also contains daemon panics without orphaning Pebble.
func integrationDNSSubprocess(t *testing.T) bool {
	t.Helper()
	if *integrationDNSChild == t.Name() {
		return false
	}
	postgresURL := testutil.PostgresURL(t)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("rejected nonlocal integration request: %s %s", r.Method, r.Host)
		http.Error(w, "integration tests forbid nonlocal API requests", http.StatusForbidden)
	}))
	cleanupIntegrationHTTPServer(t, proxy, nil)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	testRun := "^" + regexp.QuoteMeta(t.Name()) + "$"
	if _, subtests, ok := strings.Cut(flag.Lookup("test.run").Value.String(), "/"); ok {
		testRun += "/" + subtests
	}
	command := exec.Command(executable,
		"-test.run="+testRun, "-test.v", "-test.timeout=170s",
		"-tnl-test-tier="+string(testutil.TestTierDNS),
		"-tnl-test-postgres-url="+postgresURL,
		"-tnl-dns-child="+t.Name(),
	)
	cleanupGroup := isolateIntegrationDNSProcess(t, command)
	temporaryDirectory := t.TempDir()
	command.Env = append(os.Environ(),
		"TMPDIR="+temporaryDirectory,
		"AWS_ACCESS_KEY_ID=tnl-integration-only", "AWS_SECRET_ACCESS_KEY=not-a-real-aws-secret",
		"AWS_SESSION_TOKEN=", "AWS_EC2_METADATA_DISABLED=true", "AWS_PROFILE=",
		"AWS_CONFIG_FILE="+filepath.Join(temporaryDirectory, "absent-config"),
		"AWS_SHARED_CREDENTIALS_FILE="+filepath.Join(temporaryDirectory, "absent-credentials"),
		"AWS_ENDPOINT_URL_ROUTE_53=http://127.0.0.1:1", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=false",
		"HTTP_PROXY="+proxy.URL, "HTTPS_PROXY="+proxy.URL, "ALL_PROXY="+proxy.URL,
		"http_proxy="+proxy.URL, "https_proxy="+proxy.URL,
		"NO_PROXY=127.0.0.1,localhost,::1", "no_proxy=127.0.0.1,localhost,::1",
	)
	var output synchronizedBuffer
	command.Stdout, command.Stderr = &output, &output
	owner, err := startOwnedCommand(command, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.shutdown(time.Second, 5*time.Second); err != nil {
			t.Errorf("isolated DNS shutdown: %v", err)
		}
		cleanupGroup()
	}()
	if err := waitForDone(ctx, owner.done); err != nil {
		t.Fatalf("isolated runtime DNS test deadline: %v\n%s", err, output.String())
	}
	if err := owner.result(); err != nil {
		t.Fatalf("isolated runtime DNS test: %v\n%s", err, output.String())
	}
	t.Logf("%s", output.String())
	return true
}

type integrationDNSRecord struct {
	Name   string
	Type   string
	TTL    int
	Values []integrationDNSValue `xml:"ResourceRecords>ResourceRecord"`
}

type integrationDNSValue struct {
	Value string `xml:"Value"`
}

type integrationDNSZone struct {
	ID              string `xml:"Id"`
	Name            string
	CallerReference string
	Config          struct{ PrivateZone bool }
	records         map[string]integrationDNSRecord
}

type integrationDNSChange struct {
	Action string
	Record integrationDNSRecord `xml:"ResourceRecordSet"`
	zoneID string
}

// This is only the Route 53 HTTP wire boundary, not a replacement provider or
// verifier. Records written by the real SDK are served to tnld and Pebble.
type integrationRoute53 struct {
	address      string
	server       *httptest.Server
	mu           sync.Mutex
	zoneID       string
	zone         *integrationDNSZone
	changes      []integrationDNSChange
	beforeChange func(context.Context, integrationDNSChange) error
}

func newIntegrationRoute53(t *testing.T, zoneID, domain string) *integrationRoute53 {
	t.Helper()
	if *integrationDNSChild == "" {
		t.Fatal("Route 53 fixture requires the isolated, network-restricted test subprocess")
	}
	f := &integrationRoute53{
		address: "127.0.0.1:53", zoneID: zoneID,
		zone: &integrationDNSZone{
			ID: "/hostedzone/" + zoneID, Name: dns.Fqdn(domain), CallerReference: "fixture-" + zoneID,
			records: make(map[string]integrationDNSRecord),
		},
	}
	listener, err := net.Listen("tcp", f.address)
	if err != nil {
		t.Fatalf("authoritative DNS integration requires free TCP/UDP port 53 on localhost (CI permits unprivileged port 53): %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	packet, err := net.ListenPacket("udp", f.address)
	if err != nil {
		t.Fatalf("authoritative DNS integration requires free UDP port 53 on localhost: %v", err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	for _, server := range []*dns.Server{
		{Listener: listener, Handler: dns.HandlerFunc(f.serveDNS)},
		{PacketConn: packet, Handler: dns.HandlerFunc(f.serveDNS)},
	} {
		startOwnedDNSServer(t, server)
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.serveRoute53(t, w, r)
	}))
	cleanupIntegrationHTTPServer(t, f.server, nil)
	t.Setenv("AWS_ENDPOINT_URL_ROUTE_53", f.server.URL)
	return f
}

func (f *integrationRoute53) setBeforeChange(hook func(context.Context, integrationDNSChange) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beforeChange = hook
}

func (f *integrationRoute53) serveRoute53(t *testing.T, w http.ResponseWriter, r *http.Request) {
	if r.Host != strings.TrimPrefix(f.server.URL, "http://") ||
		!strings.Contains(r.Header.Get("Authorization"), "Credential=tnl-integration-only/") {
		t.Error("Route 53 request did not use the local endpoint and explicit dummy credentials")
		http.Error(w, "unexpected request", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	write := func(name string, value any) {
		err := xml.NewEncoder(w).EncodeElement(value, xml.StartElement{Name: xml.Name{Local: name},
			Attr: []xml.Attr{{Name: xml.Name{Local: "xmlns"}, Value: "https://route53.amazonaws.com/doc/2013-04-01/"}}})
		if err != nil {
			t.Errorf("Route 53 response: %v", err)
		}
	}
	path := strings.TrimPrefix(r.URL.Path, "/2013-04-01/")
	parts := strings.Split(path, "/")
	if len(parts) == 3 && parts[0] == "hostedzone" && parts[1] == f.zoneID && parts[2] == "rrset" && r.Method == http.MethodPost {
		var input struct {
			Changes []integrationDNSChange `xml:"ChangeBatch>Changes>Change"`
		}
		if err := xml.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&input); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := f.applyChanges(ctx, input.Changes); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		write("ChangeResourceRecordSetsResponse", struct {
			Status string `xml:"ChangeInfo>Status"`
		}{"INSYNC"})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var zone *integrationDNSZone
	if len(parts) >= 2 && parts[1] == f.zoneID {
		zone = f.zone
	}
	switch {
	case len(parts) == 2 && parts[0] == "hostedzone" && zone != nil && r.Method == http.MethodGet:
		write("GetHostedZoneResponse", struct {
			HostedZone  *integrationDNSZone
			Nameservers []string `xml:"DelegationSet>NameServers>NameServer"`
		}{zone, []string{"ns1.integration.test", "ns2.integration.test"}})
	case len(parts) == 3 && parts[2] == "rrset" && zone != nil && r.Method == http.MethodGet:
		var records []integrationDNSRecord
		for _, record := range zone.records {
			if record.Name == dns.Fqdn(r.URL.Query().Get("name")) {
				records = append(records, record)
			}
		}
		slices.SortFunc(records, func(a, b integrationDNSRecord) int { return strings.Compare(a.Type, b.Type) })
		write("ListResourceRecordSetsResponse", struct {
			Records     []integrationDNSRecord `xml:"ResourceRecordSets>ResourceRecordSet"`
			IsTruncated bool
		}{Records: records})
	default:
		t.Errorf("unimplemented Route 53 request: %s %s", r.Method, r.URL.RequestURI())
		http.NotFound(w, r)
	}
}

func (f *integrationRoute53) applyChanges(ctx context.Context, changes []integrationDNSChange) error {
	f.mu.Lock()
	hook := f.beforeChange
	f.mu.Unlock()
	changes = slices.Clone(changes)
	for i := range changes {
		changes[i].Record.Name = dns.Fqdn(changes[i].Record.Name)
		changes[i].zoneID = f.zoneID
		if hook != nil {
			if err := hook(ctx, changes[i]); err != nil {
				return err
			}
		}
	}
	// Validate against the current state after the gate, then commit the entire
	// batch under one lock. Failed/canceled batches cannot partially mutate DNS.
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	records := make(map[string]integrationDNSRecord, len(f.zone.records))
	for key, record := range f.zone.records {
		records[key] = record
	}
	for _, change := range changes {
		key := change.Record.Name + "/" + change.Record.Type
		existing, exists := records[key]
		if change.Action != "CREATE" && change.Action != "UPSERT" && change.Action != "DELETE" ||
			change.Action == "CREATE" && exists || change.Action == "DELETE" &&
			(!exists || !slices.Equal(existing.Values, change.Record.Values) || existing.TTL != change.Record.TTL) {
			return fmt.Errorf("invalid Route 53 %s for %s", change.Action, key)
		}
		if change.Action == "DELETE" {
			delete(records, key)
		} else {
			records[key] = change.Record
		}
	}
	f.zone.records = records
	f.changes = append(f.changes, changes...)
	return nil
}

func (f *integrationRoute53) serveDNS(w dns.ResponseWriter, request *dns.Msg) {
	f.mu.Lock()
	defer f.mu.Unlock()
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	for _, question := range request.Question {
		name := strings.ToLower(question.Name)
		var zone *integrationDNSZone
		if name == f.zone.Name || strings.HasSuffix(name, "."+f.zone.Name) {
			zone = f.zone
		}
		add := func(value string) {
			record, err := dns.NewRR(fmt.Sprintf("%s 1 IN %s %s", name, dns.TypeToString[question.Qtype], value))
			if err == nil {
				response.Answer = append(response.Answer, record)
			}
		}
		if question.Qtype == dns.TypeA && (strings.HasPrefix(name, "ns1.") || strings.HasPrefix(name, "ns2.") ||
			strings.HasPrefix(name, "control.") || strings.HasPrefix(name, "relay.") || strings.HasPrefix(name, "relay-")) {
			add("127.0.0.1")
		} else if zone != nil {
			switch {
			case name == zone.Name && question.Qtype == dns.TypeNS:
				add("ns1.integration.test.")
				add("ns2.integration.test.")
			case name == zone.Name && question.Qtype == dns.TypeSOA:
				add("ns1.integration.test. hostmaster.integration.test. 1 60 60 60 1")
			default:
				for _, value := range zone.records[name+"/"+dns.TypeToString[question.Qtype]].Values {
					add(value.Value)
				}
			}
		}
	}
	_ = w.WriteMsg(response)
}
