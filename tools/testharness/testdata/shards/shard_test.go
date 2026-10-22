package shards

import (
	"flag"
	"testing"
)

var probe = flag.String("tnl-probe", "", "verify child argument forwarding")

func TestAlpha(t *testing.T)    { checkProbe(t) }
func TestAlphabet(t *testing.T) { checkProbe(t) }
func TestBeta(t *testing.T)     { checkProbe(t) }
func TestGamma(t *testing.T)    { checkProbe(t) }
func TestIgnored(t *testing.T)  { t.Fatal("excluded test executed") }

func checkProbe(t *testing.T) {
	t.Helper()
	if *probe != "kept" {
		t.Fatalf("child argument was not preserved: %q", *probe)
	}
}
