// dnsdev is a disposable, in-memory Route 53 wire fixture and authoritative DNS
// server for local development. it never contacts a DNS provider.
package main

import (
	"encoding/xml"
	"fmt"
	"log"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type record struct {
	Name   string
	Type   string
	TTL    int64
	Values []value `xml:"ResourceRecords>ResourceRecord"`
}
type value struct{ Value string }
type change struct {
	Action string
	Record record `xml:"ResourceRecordSet"`
}
type fixture struct {
	mu              sync.Mutex
	domain, address string
	records         map[string]record
}

func main() {
	f := &fixture{domain: dns.Fqdn(os.Getenv("DNS_DOMAIN")), address: os.Getenv("DNS_ADDRESS"), records: map[string]record{}}
	if f.domain == "." || f.address == "" {
		log.Fatal("DNS_DOMAIN and DNS_ADDRESS are required")
	}
	for _, network := range []string{"tcp", "udp"} {
		server := &dns.Server{Addr: ":53", Net: network, Handler: dns.HandlerFunc(f.dns)}
		go func() {
			if err := server.ListenAndServe(); err != nil {
				log.Fatal("local DNS listener failed")
			}
		}()
	}
	server := &http.Server{Addr: ":8080", Handler: http.HandlerFunc(f.route53), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	log.Fatal(server.ListenAndServe())
}

func (f *fixture) route53(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Authorization"), "Credential=tnl-local-only/") {
		http.Error(w, "local credentials required", http.StatusForbidden)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "text/xml")
	write := func(name string, data any) {
		_ = xml.NewEncoder(w).EncodeElement(data, xml.StartElement{Name: xml.Name{Local: name}, Attr: []xml.Attr{{Name: xml.Name{Local: "xmlns"}, Value: "https://route53.amazonaws.com/doc/2013-04-01/"}}})
	}
	path := strings.TrimPrefix(r.URL.Path, "/2013-04-01/")
	switch {
	case r.Method == "GET" && path == "hostedzone/local":
		write("GetHostedZoneResponse", struct {
			ID        string   `xml:"HostedZone>Id"`
			Name      string   `xml:"HostedZone>Name"`
			Reference string   `xml:"HostedZone>CallerReference"`
			NS        []string `xml:"DelegationSet>NameServers>NameServer"`
		}{"/hostedzone/local", f.domain, "local-development", []string{"ns1." + f.domain, "ns2." + f.domain}})
	case r.Method == "GET" && path == "hostedzone/local/rrset":
		var records []record
		for _, record := range f.records {
			if record.Name == dns.Fqdn(r.URL.Query().Get("name")) {
				records = append(records, record)
			}
		}
		slices.SortFunc(records, func(a, b record) int { return strings.Compare(a.Type, b.Type) })
		write("ListResourceRecordSetsResponse", struct {
			Records     []record `xml:"ResourceRecordSets>ResourceRecordSet"`
			IsTruncated bool
		}{Records: records})
	case r.Method == "POST" && path == "hostedzone/local/rrset":
		var input struct {
			Changes []change `xml:"ChangeBatch>Changes>Change"`
		}
		if xml.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&input) != nil {
			http.Error(w, "invalid DNS change", http.StatusBadRequest)
			return
		}
		next := maps.Clone(f.records)
		for _, change := range input.Changes {
			record := change.Record
			record.Name = dns.Fqdn(record.Name)
			if record.Name != f.domain && !strings.HasSuffix(record.Name, "."+f.domain) {
				http.Error(w, "outside local zone", http.StatusBadRequest)
				return
			}
			key := record.Name + "/" + record.Type
			old, exists := next[key]
			switch change.Action {
			case "CREATE":
				if exists {
					http.Error(w, "record exists", http.StatusBadRequest)
					return
				}
				next[key] = record
			case "UPSERT":
				next[key] = record
			case "DELETE":
				if !exists || old.TTL != record.TTL || !slices.Equal(old.Values, record.Values) {
					http.Error(w, "record changed", http.StatusBadRequest)
					return
				}
				delete(next, key)
			default:
				http.Error(w, "unknown DNS change", http.StatusBadRequest)
				return
			}
		}
		f.records = next
		write("ChangeResourceRecordSetsResponse", struct {
			ID     string `xml:"ChangeInfo>Id"`
			Status string `xml:"ChangeInfo>Status"`
		}{"/change/local", "INSYNC"})
	case r.Method == "GET" && path == "change/local":
		write("GetChangeResponse", struct {
			ID     string `xml:"ChangeInfo>Id"`
			Status string `xml:"ChangeInfo>Status"`
		}{"/change/local", "INSYNC"})
	default:
		http.NotFound(w, r)
	}
}

func (f *fixture) dns(w dns.ResponseWriter, request *dns.Msg) {
	f.mu.Lock()
	defer f.mu.Unlock()
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	for _, q := range request.Question {
		name := strings.ToLower(q.Name)
		add := func(value string) {
			if rr, err := dns.NewRR(fmt.Sprintf("%s 1 IN %s %s", name, dns.TypeToString[q.Qtype], value)); err == nil {
				response.Answer = append(response.Answer, rr)
			}
		}
		switch {
		case (name == "ns1."+f.domain || name == "ns2."+f.domain) && q.Qtype == dns.TypeA:
			add(f.address)
		case name == f.domain && q.Qtype == dns.TypeNS:
			add("ns1." + f.domain)
			add("ns2." + f.domain)
		case name == f.domain && q.Qtype == dns.TypeSOA:
			add("ns1." + f.domain + " hostmaster." + f.domain + " 1 60 60 60 1")
		default:
			record := f.records[name+"/"+dns.TypeToString[q.Qtype]]
			if len(record.Values) == 0 {
				_, parent, _ := strings.Cut(name, ".")
				record = f.records["*."+parent+"/"+dns.TypeToString[q.Qtype]]
			}
			for _, value := range record.Values {
				add(value.Value)
			}
		}
	}
	_ = w.WriteMsg(response)
}
