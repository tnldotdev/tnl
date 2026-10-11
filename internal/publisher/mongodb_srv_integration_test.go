package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func TestIntegrationMongoSRVSelectsVerifiedPrimaryAfterChange(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if *testMongoDBAddress == "" {
		t.Skip("requires the MongoDB integration target")
	}
	first := publicURLTestCertificate(t, "node-1.cluster.example")
	second := publicURLTestCertificate(t, "node-2.cluster.example")
	roots := x509.NewCertPool()
	roots.AddCert(first.Leaf)
	roots.AddCert(second.Leaf)
	var firstPrimary, secondPrimary atomic.Bool
	secondPrimary.Store(true)
	firstAddress := mongoTestTLSTarget(t, first, &firstPrimary)
	secondAddress := mongoTestTLSTarget(t, second, &secondPrimary)
	publicCertificate := publicURLTestCertificate(t, "mongo.example")
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "mongo.example", ServiceProtocol: controlv1.Mongodb, PublicPort: 27017,
		Target: "mongodb+srv://seed.cluster.example", TargetTLS: true,
		TargetOptions: localproxy.TargetOptions{RootCAs: roots}, Certificate: publicCertificate,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	route.tcp.mongoSRV.resolver = mongoTestSeed(
		&net.SRV{Target: "node-1.cluster.example.", Port: 27017},
		&net.SRV{Target: "node-2.cluster.example.", Port: 27017},
	).resolver
	route.tcp.mongoSRV.dial = func(ctx context.Context, _, address string) (net.Conn, error) {
		var mapped string
		switch {
		case strings.HasPrefix(address, "node-1."):
			mapped = firstAddress
		case strings.HasPrefix(address, "node-2."):
			mapped = secondAddress
		default:
			return nil, fmt.Errorf("unexpected SRV target dial: %q", address)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", mapped)
	}
	selected, err := route.tcp.mongoSRV.connect(t.Context())
	if err != nil {
		t.Fatalf("preflight mongodb primary selection: %v", err)
	}
	_ = selected.Close()
	visitMongoSRV(t, route, publicCertificate, "first")
	firstPrimary.Store(true)
	secondPrimary.Store(false)
	visitMongoSRV(t, route, publicCertificate, "after-change")
	firstPrimary.Store(false)
	selectionCtx, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	if selected, err := route.tcp.mongoSRV.connect(selectionCtx); err == nil {
		_ = selected.Close()
		t.Fatal("mongodb SRV selection forwarded to a secondary when no primary was available")
	}
	firstPrimary.Store(true)
	route.tcp.mongoSRV.roots = x509.NewCertPool()
	if selected, err := route.tcp.mongoSRV.connect(selectionCtx); err == nil {
		_ = selected.Close()
		t.Fatal("mongodb SRV selection accepted an untrusted target certificate")
	}
}

func mongoTestTLSTarget(t *testing.T, certificate tls.Certificate, primary *atomic.Bool) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	secondaryReply := mongoTestHelloReply(t, false, "")
	completed := make(chan struct{})
	go func() {
		defer close(completed)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
				secured := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				if err := secured.Handshake(); err != nil {
					return
				}
				if primary.Load() {
					backend, err := net.DialTimeout("tcp", *testMongoDBAddress, 5*time.Second)
					if err != nil {
						return
					}
					defer backend.Close()
					_ = connection.SetDeadline(time.Time{})
					_, _ = streamcopy.Copy(secured, backend)
					return
				}
				var header [4]byte
				if _, err := io.ReadFull(secured, header[:]); err != nil {
					return
				}
				length := binary.LittleEndian.Uint32(header[:])
				if length < 4 || length > 1024 {
					return
				}
				_, err := io.CopyN(io.Discard, secured, int64(length-4))
				if err == nil {
					_, _ = secured.Write(secondaryReply)
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-completed })
	return listener.Addr().String()
}

func visitMongoSRV(t *testing.T, route *PublicURLServer, certificate tls.Certificate, value string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(
		"mongodb://tnl_test:testpass@mongo.example:27017/admin?tls=true&directConnection=true&authSource=admin&serverSelectionTimeoutMS=10000",
	).SetTLSConfig(&tls.Config{ServerName: "mongo.example", RootCAs: rootsForCertificate(t, certificate), MinVersion: tls.VersionTLS12}).
		SetDialer(mongodbVisitorDialer{t: t, route: route}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = client.Disconnect(cleanup)
	}()
	database := client.Database("tnl_test")
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = database.Drop(cleanup)
	}()
	collection := database.Collection("srv_targets")
	if _, err := collection.InsertOne(ctx, bson.D{{Key: "value", Value: value}}); err != nil {
		t.Fatal(err)
	}
	var found struct {
		Value string `bson:"value"`
	}
	if err := collection.FindOne(ctx, bson.D{{Key: "value", Value: value}}).Decode(&found); err != nil || found.Value != value {
		t.Fatalf("selected MongoDB primary read = %q, %v", found.Value, err)
	}
}
