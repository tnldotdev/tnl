package children

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
)

var (
	address   = flag.String("tnl-parent-address", "", "fixture readiness and cleanup handshake")
	artifacts = flag.String("tnl-artifacts", "", "artifacts that must survive child cleanup")
	record    = flag.String("tnl-record", "", "child cleanup and reaping evidence")
	fail      = flag.Bool("tnl-parent-fail", false, "fail after joining the child")
)

func TestParent(t *testing.T) {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(interrupt)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestChild$", "-tnl-parent-address="+*address, "-tnl-artifacts="+*artifacts, "-tnl-record="+*record)
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Run(); err != nil {
		t.Fatal(err)
	}
	appendRecord(t, "parent joined child\n")
	if *fail {
		t.Fatal("independent test failure after cancellation")
	}
}

func TestChild(t *testing.T) {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(interrupt)
	connection, err := net.Dial("tcp", *address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := fmt.Fprintln(connection, os.Getpid()); err != nil {
		t.Fatal(err)
	}
	<-interrupt
	if _, err := fmt.Fprintln(connection, "stopping"); err != nil {
		t.Fatal(err)
	}
	var release string
	if _, err := fmt.Fscanln(connection, &release); err != nil {
		t.Fatal(err)
	}
	if release != "finish" {
		t.Fatalf("unexpected cleanup release %q", release)
	}
	if _, err := os.Stat(*artifacts); err != nil {
		t.Fatalf("artifacts removed before child cleanup: %v", err)
	}
	appendRecord(t, "child cleaned\n")
}

func TestUnresponsive(t *testing.T) {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(interrupt)
	connection, err := net.Dial("tcp", *address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := fmt.Fprintln(connection, os.Getpid()); err != nil {
		t.Fatal(err)
	}
	<-interrupt
	if _, err := fmt.Fprintln(connection, "stopping"); err != nil {
		t.Fatal(err)
	}
	select {}
}

func appendRecord(t *testing.T, entry string) {
	t.Helper()
	file, err := os.OpenFile(*record, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(entry); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
