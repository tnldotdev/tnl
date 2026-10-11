package publisher

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var testMongoDBAddress = flag.String("tnl-test-mongodb-address", "", "disposable mongod host and port")

func TestMongoDBForwardingRequiresVisitorTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	forwarded := make(chan int, 1)
	go func() {
		backend, err := listener.Accept()
		if err != nil {
			return
		}
		defer backend.Close()
		_ = backend.SetReadDeadline(time.Now().Add(5 * time.Second))
		count, _ := backend.Read(make([]byte, 16))
		forwarded <- count
	}()
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "mongo.example", ServiceProtocol: controlv1.Mongodb, PublicPort: 27017,
		Target: listener.Addr().String(), Certificate: publicURLTestCertificate(t, "mongo.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	visitor := openDatabaseVisitor(t, route, 27017)
	if _, err := visitor.Write([]byte("plaintext mongo")); err != nil {
		t.Fatal(err)
	}
	if _, err := visitor.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("plaintext MongoDB visitor read = %v, want EOF", err)
	}
	if got := awaitPublisherTest(t, forwarded); got != 0 {
		t.Fatalf("plaintext MongoDB bytes reached private target: %d", got)
	}
}

type mongodbVisitorDialer struct {
	t     *testing.T
	route *PublicURLServer
}

func (d mongodbVisitorDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	return dialDatabaseVisitor(d.t, d.route, 27017)
}

func TestIntegrationMongoDBClient(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if *testMongoDBAddress == "" {
		t.Skip("requires the MongoDB integration target")
	}
	certificate := publicURLTestCertificate(t, "mongo.example")
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "mongo.example", ServiceProtocol: controlv1.Mongodb, PublicPort: 27017,
		Target: *testMongoDBAddress, Certificate: certificate,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	uri := "mongodb://tnl_test:testpass@mongo.example:27017/admin?tls=true&directConnection=true&authSource=admin&serverSelectionTimeoutMS=10000"
	client, err := mongo.Connect(options.Client().ApplyURI(uri).
		SetTLSConfig(&tls.Config{ServerName: "mongo.example", RootCAs: rootsForCertificate(t, certificate), MinVersion: tls.VersionTLS12}).
		SetDialer(mongodbVisitorDialer{t: t, route: route}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = client.Disconnect(cleanup)
	}()
	if err := client.Ping(ctx, nil); err != nil {
		t.Fatal(err)
	}
	database := client.Database("tnl_test")
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = database.Drop(cleanup)
	}()
	collection := database.Collection("tunnel")
	if _, err := collection.InsertOne(ctx, bson.D{{Key: "value", Value: "ok"}}); err != nil {
		t.Fatal(err)
	}
	var document struct {
		Value string `bson:"value"`
	}
	if err := collection.FindOne(ctx, bson.D{{Key: "value", Value: "ok"}}).Decode(&document); err != nil || document.Value != "ok" {
		t.Fatalf("MongoDB document value = %q, %v", document.Value, err)
	}
}
