package dns

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

func TestRoute53ProviderListsEscapedWildcardAcrossPages(t *testing.T) {
	const hostname = "*.member.tunnels.example.test"
	const listedName = `\052.member.tunnels.example.test.`
	const otherName = `\052.other.tunnels.example.test.`
	for _, test := range []struct {
		name, cursor, secondName string
		requests, records        int
	}{
		{"same escaped name", listedName, listedName, 2, 2},
		{"different record name", listedName, otherName, 2, 1},
		{"different cursor name", otherName, listedName, 1, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				page := requests.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/2013-04-01/hostedzone/Z123/rrset" {
					t.Errorf("unexpected Route 53 request: %s %s", r.Method, r.URL)
					http.Error(w, "unexpected operation", http.StatusBadRequest)
					return
				}
				query := r.URL.Query()
				wantName, wantType := hostname+".", ""
				if page == 2 {
					wantName, wantType = listedName, string(types.RRTypeAaaa)
				}
				if page > 2 || query.Get("name") != wantName || query.Get("type") != wantType ||
					query.Get("identifier") != "" || query.Get("maxitems") != "10" {
					t.Errorf("page %d cursor = %v, want name=%q type=%q", page, query, wantName, wantType)
					http.Error(w, "unexpected cursor", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "text/xml")
				if page == 1 {
					_, _ = fmt.Fprintf(w, `<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets><ResourceRecordSet><Name>%s</Name><Type>A</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>192.0.2.10</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets><IsTruncated>true</IsTruncated><NextRecordName>%s</NextRecordName><NextRecordType>AAAA</NextRecordType><MaxItems>10</MaxItems></ListResourceRecordSetsResponse>`, listedName, test.cursor)
					return
				}
				_, _ = fmt.Fprintf(w, `<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets><ResourceRecordSet><Name>%s</Name><Type>AAAA</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>2001:db8::10</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>10</MaxItems></ListResourceRecordSetsResponse>`, test.secondName)
			}))
			t.Cleanup(server.Close)
			client := route53.New(route53.Options{
				Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), Retryer: aws.NopRetryer{},
				Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
					return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
				}),
			})
			provider, err := NewRoute53Provider(client)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			sets, err := provider.listRecordSets(ctx, "/hostedzone/Z123", hostname)
			a := simpleRecordSet(hostname, types.RRTypeA, []string{"192.0.2.10"})
			a.Name = aws.String(listedName)
			want := []types.ResourceRecordSet{*a}
			if test.records == 2 {
				aaaa := simpleRecordSet(hostname, types.RRTypeAaaa, []string{"2001:db8::10"})
				aaaa.Name = aws.String(listedName)
				want = append(want, *aaaa)
			}
			if err != nil || requests.Load() != int32(test.requests) || !reflect.DeepEqual(sets, want) {
				t.Fatalf("listed records = %#v, requests=%d, error=%v; want %#v in %d requests", sets, requests.Load(), err, want, test.requests)
			}
		})
	}
}

func TestRoute53RecordNameKeepsExactWildcardIdentity(t *testing.T) {
	const hostname = "*.member.tunnels.example.test."
	for _, test := range []struct {
		name, input, want string
		matches           bool
	}{
		{"literal", hostname, hostname, true},
		{"escaped", `\052.member.tunnels.example.test.`, hostname, true},
		{"escaped uppercase", `\052.MEMBER.TUNNELS.EXAMPLE.TEST.`, hostname, true},
		{"other member", `\052.other.tunnels.example.test.`, "*.other.tunnels.example.test.", false},
		{"member lookalike", `\052.notmember.tunnels.example.test.`, "*.notmember.tunnels.example.test.", false},
		{"different escape", `\053.member.tunnels.example.test.`, `\053.member.tunnels.example.test.`, false},
		{"no escape", "052.member.tunnels.example.test.", "052.member.tunnels.example.test.", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := route53RecordName(test.input)
			if got != test.want || (got == hostname) != test.matches {
				t.Fatalf("normalized %q to %q, want %q (matches=%t)", test.input, got, test.want, test.matches)
			}
		})
	}
}
