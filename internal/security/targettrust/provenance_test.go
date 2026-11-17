package targettrust

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestSystemTrustCapturePreservesHostnameProvenance(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "origin", true: "explicit same hostname"}[explicit], func(t *testing.T) {
			host := "target.example"
			setting := config.TrustSource{CA: "system"}
			if explicit {
				setting.Hostname = &host
			}
			snapshot, err := NewCache(nil).Capture(t.Context(), "", host+":443", setting)
			if err != nil {
				t.Fatal(err)
			}
			declaration, err := snapshot.Declaration()
			if err != nil {
				t.Fatal(err)
			}
			restored, err := declaration.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			portableHostname := ""
			if explicit {
				portableHostname = host
			}
			portable, err := CapturePortable(t.Context(), "http", host+":443", "system", portableHostname)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.HostnameFromTarget != !explicit || declaration.HostnameFromTarget != !explicit ||
				restored.HostnameFromTarget != !explicit || portable.HostnameFromTarget != !explicit {
				t.Fatal("capture lost whether the hostname override was omitted", snapshot, declaration, restored, portable)
			}
			pinned, err := NewDeclaration(host, nil)
			if err != nil {
				t.Fatal(err)
			}
			if pinned.HostnameFromTarget || pinned.Digest != declaration.Digest {
				t.Fatal("explicit declaration became automatic or provenance changed trust material")
			}
			pinnedSnapshot, _ := pinned.Snapshot()
			if pinnedSnapshot.Digest != snapshot.Digest {
				t.Fatal("configuration provenance changed the runtime trust digest")
			}
		})
	}
}

func TestCustomTrustCannotFollowTargetHostname(t *testing.T) {
	pem, _ := testCA(t)
	snapshot, err := CapturePEM("target.example", pem)
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := snapshot.Declaration()
	if err != nil {
		t.Fatal(err)
	}
	declaration.HostnameFromTarget = true
	if declaration.Validate() == nil {
		t.Fatal("custom declaration accepted automatic hostname replacement")
	}
	snapshot.HostnameFromTarget = true
	if snapshot.Validate() == nil {
		t.Fatal("custom trust accepted automatic hostname replacement")
	}
}
