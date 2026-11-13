package connector

import (
	"errors"
	"net"
	"path/filepath"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectorLocalPortIgnoresPublicEndpoint(t *testing.T) {
	for _, protocol := range []controlv1.ServiceProtocol{"http", "postgres", "mysql", "tcp", "kubernetes"} {
		t.Run(string(protocol), func(t *testing.T) {
			ctx := t.Context()
			root := filepath.Join(t.TempDir(), "state")
			database, err := clientstate.OpenWithOptions(ctx, root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
			if err != nil {
				t.Fatal(err)
			}
			store, err := database.Server(ctx, "https://control.example.test")
			if err != nil {
				t.Fatal(err)
			}
			service := controlv1.Service{Id: "svc_0123456789ABCDEFGHIJKL", Name: "orders", Protocol: protocol,
				Endpoint: &controlv1.ServiceEndpoint{Hostname: "orders.example.test", Port: 25443}}
			// an existing assignment must survive the cutover, even if it was
			// originally selected from the public endpoint port.
			first, err := store.ListenServiceAt(ctx, "identity", service.Id, "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := first.Addr().String()
			_ = first.Close()
			first, err = listenConnector(ctx, store, "identity", service, address)
			if err != nil {
				t.Fatal(err)
			}
			_ = first.Close()
			_ = database.Close()

			database, err = clientstate.OpenWithOptions(ctx, root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			store, err = database.Server(ctx, "https://control.example.test")
			if err != nil {
				t.Fatal(err)
			}
			for _, public := range []bool{true, false, true} {
				service.Name = "renamed"
				service.Endpoint.Public = public
				service.Endpoint.Port++
				listener, err := listenConnector(ctx, store, "identity", service, "")
				if err != nil {
					t.Fatal(err)
				}
				if listener.Addr().String() != address {
					t.Fatal("endpoint transition changed the local assignment")
				}
				_ = listener.Close()
			}
			occupied, err := net.Listen("tcp4", address)
			if err != nil {
				t.Fatal(err)
			}
			defer occupied.Close()
			_, err = listenConnector(ctx, store, "identity", service, "")
			var conflict *clientstate.PortOccupiedError
			if !errors.As(err, &conflict) {
				t.Fatalf("saved port was silently renumbered: %v", err)
			}
		})
	}
}

func TestConnectorFirstPortDoesNotBindPublicPort(t *testing.T) {
	ctx := t.Context()
	database, err := clientstate.OpenWithOptions(ctx, filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := database.Server(ctx, "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	public, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer public.Close()
	service := controlv1.Service{Id: "svc_0123456789ABCDEFGHIJKL", Protocol: "http",
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "api.example.test", Port: public.Addr().(*net.TCPAddr).Port, Public: true}}
	listener, err := listenConnector(ctx, store, "identity", service, "")
	if err != nil {
		t.Fatal("public port occupancy prevented a local connection", err)
	}
	defer listener.Close()
	if listener.Addr().String() == public.Addr().String() {
		t.Fatal("public endpoint selected the local port")
	}
	port, found, err := store.ServicePort(ctx, "identity", service.Id)
	if err != nil || !found || port != listener.Addr().(*net.TCPAddr).Port {
		t.Fatal("first local assignment was not persisted", port, found, err)
	}
}
