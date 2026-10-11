package publisher

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type mongoTestDNS struct {
	records []*net.SRV
	txt     []string
}

func (d *mongoTestDNS) LookupSRV(_ context.Context, service, protocol, name string) (string, []*net.SRV, error) {
	if service != "mongodb" || protocol != "tcp" || name != "seed.cluster.example" {
		return "", nil, errors.New("unexpected mongodb seed")
	}
	return "", d.records, nil
}

func (d *mongoTestDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if name != "seed.cluster.example" {
		return nil, errors.New("unexpected mongodb TXT hostname")
	}
	return d.txt, nil
}

func mongoTestSeed(records ...*net.SRV) *mongoSRVTarget {
	return &mongoSRVTarget{seed: "seed.cluster.example", resolver: &mongoTestDNS{records: records}}
}

func TestMongoSRVTargetValidatesSeedAndTLS(t *testing.T) {
	for _, target := range []string{
		"mongodb+srv://user:pass@seed.cluster.example", "mongodb+srv://seed.cluster.example:27017",
		"mongodb+srv://seed.cluster.example/app", "mongodb+srv://seed.cluster.example/?tls=false",
		"mongodb+srv://SEED.cluster.example", "mongodb+srv://localhost",
	} {
		if _, err := parseMongoSRVTarget(target, nil); err == nil {
			t.Fatalf("invalid private SRV seed accepted: %q", target)
		}
	}
	for _, test := range []struct {
		tls     bool
		tlsName string
		valid   bool
	}{
		{tls: true, valid: true}, {tls: false}, {tls: true, tlsName: "seed.cluster.example"},
	} {
		config := PublicURLServerConfig{
			ServiceProtocol: controlv1.Mongodb, PublicPort: 27017,
			Target: "mongodb+srv://seed.cluster.example", TargetTLS: test.tls, TargetTLSName: test.tlsName,
			TargetOptions: localproxy.TargetOptions{},
		}
		forwarding, err := newTCPForwarding(config)
		if test.valid && (err != nil || forwarding.mongoSRV == nil || forwarding.backendTLS != nil) {
			t.Fatalf("valid mongodb SRV forwarding = %+v, %v", forwarding, err)
		}
		if !test.valid && err == nil {
			t.Fatalf("invalid mongodb SRV TLS settings accepted: %+v", test)
		}
	}
}

func TestMongoSRVRecordsConstrainTargetsAndReplicaSet(t *testing.T) {
	good := &net.SRV{Target: "first.cluster.example.", Port: 27017}
	seed := mongoTestSeed(good)
	seed.resolver.(*mongoTestDNS).txt = []string{"authSource=admin&replicaSet=rs0"}
	addresses, setName, err := seed.hosts(t.Context())
	if err != nil || setName != "rs0" || !reflect.DeepEqual(addresses, []string{"first.cluster.example:27017"}) {
		t.Fatalf("validated mongodb SRV targets = %v, %q, %v", addresses, setName, err)
	}
	for _, test := range []struct {
		records []*net.SRV
		txt     []string
	}{
		{records: nil},
		{records: []*net.SRV{{Target: "first.other.example.", Port: 27017}}},
		{records: []*net.SRV{{Target: "seed.cluster.example.", Port: 27017}}},
		{records: []*net.SRV{{Target: "first.cluster.example.", Port: 0}}},
		{records: []*net.SRV{good, good}},
		{records: []*net.SRV{good}, txt: []string{"tls=false"}},
		{records: []*net.SRV{good}, txt: []string{"authSource=admin", "replicaSet=rs0"}},
	} {
		seed := mongoTestSeed(test.records...)
		seed.resolver.(*mongoTestDNS).txt = test.txt
		if _, _, err := seed.hosts(t.Context()); err == nil {
			t.Fatalf("invalid mongodb SRV records accepted: %+v", test)
		}
	}
}

func mongoTestHelloReply(t *testing.T, primary bool, setName string, mongos ...bool) []byte {
	t.Helper()
	fields := bson.D{{Key: "ok", Value: 1.0}, {Key: "isWritablePrimary", Value: primary}, {Key: "setName", Value: setName}}
	if len(mongos) != 0 && mongos[0] {
		fields = append(fields, bson.E{Key: "msg", Value: "isdbgrid"})
	}
	document, err := bson.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 21+len(document))
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(frame)))
	binary.LittleEndian.PutUint32(frame[8:12], 1)
	binary.LittleEndian.PutUint32(frame[12:16], 2013)
	copy(frame[21:], document)
	return frame
}

func TestMongoSRVProbeChoosesOnlyExpectedWritableMember(t *testing.T) {
	for _, test := range []struct {
		name    string
		primary bool
		setName string
		mongos  bool
		reject  bool
	}{
		{name: "primary", primary: true, setName: "rs0"},
		{name: "mongos", mongos: true},
		{name: "secondary", setName: "rs0", reject: true},
		{name: "wrong replica set", primary: true, setName: "elsewhere", reject: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			reply := mongoTestHelloReply(t, test.primary, test.setName, test.mongos)
			go func() {
				defer server.Close()
				var header [4]byte
				if _, err := io.ReadFull(server, header[:]); err != nil {
					return
				}
				length := binary.LittleEndian.Uint32(header[:])
				if length < 4 || length > 1024 {
					return
				}
				request := make([]byte, length-4)
				if _, err := io.ReadFull(server, request); err != nil {
					return
				}
				_, _ = server.Write(reply)
			}()
			expectedSet := "rs0"
			if test.mongos {
				expectedSet = ""
			}
			err := probeMongoPrimary(client, expectedSet)
			if test.reject && err == nil || !test.reject && err != nil {
				t.Fatalf("probe mongodb %s = %v", test.name, err)
			}
		})
	}
}
