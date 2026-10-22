package daemon

import (
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestIngressBindsExactServiceInventory(t *testing.T) {
	address := unusedTCPAddress(t)
	_, value, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(value)
	listener, err := listenIngress("127.0.0.1:0", []tcpport.Range{{First: port, Last: port}}, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	// server-first traffic must be accepted without a ClientHello or any byte.
	client, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if accepted.LocalAddr().String() != address {
		t.Fatalf("destination = %s", accepted.LocalAddr())
	}
	if _, err := accepted.Write([]byte("greeting")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var response [8]byte
	if n, err := client.Read(response[:]); err != nil || string(response[:n]) != "greeting" {
		t.Fatalf("server-first reply = %q, %v", response[:n], err)
	}
	_ = listener.Close()
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed accept = %v", err)
	}
	if connection, err := net.DialTimeout("tcp", address, time.Second); err == nil {
		_ = connection.Close()
		t.Fatal("drained service port remained open")
	}
}

func TestIngressInventoryBindFailureClosesPrimary(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port
	primary := unusedTCPAddress(t)
	if listener, err := listenIngress(primary, []tcpport.Range{{First: port, Last: port}}, false); err == nil {
		_ = listener.Close()
		t.Fatal("occupied inventory was accepted")
	}
	check, err := net.Listen("tcp", primary)
	if err != nil {
		t.Fatalf("primary leaked on bind failure: %v", err)
	}
	_ = check.Close()
}
