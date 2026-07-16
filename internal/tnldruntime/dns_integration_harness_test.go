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

// Start a fresh process before net/http caches proxy settings. Even if the SDK
// ignores the endpoint override, its public API requests hit a rejecting proxy.
// Process-group cleanup also contains daemon panics without orphaning Pebble.
func integrationDNSSubprocess(t *testing.T) bool {
	t.Helper()
	if os.Getenv("TNL_TEST_DNS_CHILD") == t.Name() {
		return false
	}
	testutil.PostgresURL(t)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("rejected nonlocal integration request: %s %s", r.Method, r.Host)
		http.Error(w, "integration tests forbid nonlocal API requests", http.StatusForbidden)
	}))
	t.Cleanup(proxy.Close)
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
	command := exec.CommandContext(ctx, executable, "-test.run="+testRun, "-test.v", "-test.timeout=170s")
	defer isolateIntegrationDNSProcess(t, command)()
	temporaryDirectory := t.TempDir()
	command.Env = append(os.Environ(),
		"TNL_TEST_DNS_CHILD="+t.Name(),
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
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated runtime DNS test: %v\n%s", err, output)
	}
	t.Logf("%s", output)
	return true
}

type integrationDNSRecord struct {
	Name   string
	Type   string
	TTL    int
	Values []string `xml:"ResourceRecords>ResourceRecord>Value"`
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
	beforeChange func(integrationDNSChange)
}

func newIntegrationRoute53(t *testing.T, zoneID, domain string) *integrationRoute53 {
	t.Helper()
	if os.Getenv("TNL_TEST_DNS_CHILD") == "" {
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
		t.Fatalf("authoritative DNS integration requires free loopback TCP/UDP port 53 (CI permits unprivileged port 53): %v", err)
	}
	packet, err := net.ListenPacket("udp", f.address)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("authoritative DNS integration requires free loopback UDP port 53: %v", err)
	}
	for _, server := range []*dns.Server{
		{Listener: listener, Handler: dns.HandlerFunc(f.serveDNS)},
		{PacketConn: packet, Handler: dns.HandlerFunc(f.serveDNS)},
	} {
		done := make(chan error, 1)
		go func() { done <- server.ActivateAndServe() }()
		t.Cleanup(func() {
			_ = server.Shutdown()
			if err := <-done; err != nil {
				t.Errorf("authoritative DNS server: %v", err)
			}
		})
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.serveRoute53(t, w, r)
	}))
	t.Cleanup(f.server.Close)
	t.Setenv("AWS_ENDPOINT_URL_ROUTE_53", f.server.URL)
	return f
}

func (f *integrationRoute53) setBeforeChange(hook func(integrationDNSChange)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beforeChange = hook
}

func (f *integrationRoute53) serveRoute53(t *testing.T, w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	case len(parts) == 3 && parts[2] == "rrset" && zone != nil && r.Method == http.MethodPost:
		var input struct {
			Changes []integrationDNSChange `xml:"ChangeBatch>Changes>Change"`
		}
		if err := xml.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		for _, change := range input.Changes {
			change.Record.Name = dns.Fqdn(change.Record.Name)
			change.zoneID = parts[1]
			if f.beforeChange != nil {
				f.beforeChange(change)
			}
			key := change.Record.Name + "/" + change.Record.Type
			existing, exists := zone.records[key]
			if change.Action != "CREATE" && change.Action != "UPSERT" && change.Action != "DELETE" ||
				change.Action == "CREATE" && exists || change.Action == "DELETE" &&
				(!exists || !slices.Equal(existing.Values, change.Record.Values) || existing.TTL != change.Record.TTL) {
				t.Errorf("invalid Route 53 %s for %s", change.Action, key)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if change.Action == "DELETE" {
				delete(zone.records, key)
			} else {
				zone.records[key] = change.Record
			}
			f.changes = append(f.changes, change)
		}
		write("ChangeResourceRecordSetsResponse", struct {
			Status string `xml:"ChangeInfo>Status"`
		}{"INSYNC"})
	default:
		t.Errorf("unimplemented Route 53 request: %s %s", r.Method, r.URL.RequestURI())
		http.NotFound(w, r)
	}
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
					add(value)
				}
			}
		}
	}
	_ = w.WriteMsg(response)
}
