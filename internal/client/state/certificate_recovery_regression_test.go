package clientstate

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestPublisherCertificatePartialRestoreCannotHideMissingPlan(t *testing.T) {
	store := testStore(t, filepath.Join(t.TempDir(), "state"), "https://server.example")
	id, _ := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	planA := exactCertificateTestPlan()
	a, err := store.CertificatesForPublisher("team", id, planA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Pending(t.Context(), "route.example"); err != nil {
		t.Fatal(err)
	}
	planB := planA
	planB.CacheKey, planB.Scope, planB.Identifiers = "current.example", "current.example", []string{"current.example"}
	b, err := store.CertificatesForPublisher("team", id, planB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Pending(t.Context(), "current.example"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(b.files.Path(), certificateFilename(b.planJSON))); err != nil {
		t.Fatal(err)
	}
	if found, err := store.PublisherCertificateMaterialExists(t.Context(), "team", id); err == nil && found {
		t.Fatal("old plan A masked loss of current plan B")
	}
	if _, err := b.Pending(t.Context(), "current.example"); err == nil {
		t.Fatal("missing plan silently generated a new key")
	}
}

func TestPublisherCertificateCurrentCheckpointSnapshotsFailClosed(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "older"} {
		t.Run(mode, func(t *testing.T) {
			store := testStore(t, filepath.Join(t.TempDir(), "state"), "https://server.example")
			id, _ := opaqueid.New(opaqueid.PublisherIdentityPrefix)
			plan := exactCertificateTestPlan()
			a, err := store.CertificatesForPublisher("team", id, plan)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.Pending(t.Context(), "route.example"); err != nil {
				t.Fatal(err)
			}
			checkpoint, found, err := a.files.Read("certificate-plans-v1.json", maxCertificateFileBytes)
			if err != nil || !found {
				t.Fatal("plan checkpoint not durable before Pending returned", err)
			}
			plan.CacheKey, plan.Scope, plan.Identifiers = "next.example", "next.example", []string{"next.example"}
			b, err := store.CertificatesForPublisher("team", id, plan)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.Pending(t.Context(), "next.example"); err != nil {
				t.Fatal(err)
			}
			material, _, err := b.files.Read(certificateFilename(b.planJSON), maxCertificateFileBytes)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing":
				err = os.Remove(filepath.Join(a.files.Path(), "certificate-plans-v1.json"))
			case "corrupt":
				err = a.files.Write("certificate-plans-v1.json", []byte(`{"version":1,"plans":null}`))
			case "older":
				err = a.files.Write("certificate-plans-v1.json", checkpoint)
			}
			if err != nil {
				t.Fatal(err)
			}
			if found, err := store.PublisherCertificateMaterialExists(t.Context(), "team", id); err == nil && found {
				t.Fatal("incomplete current checkpoint accepted")
			}
			if _, err := b.Pending(t.Context(), "next.example"); err == nil {
				t.Fatal("checkpoint was reconstructed from material")
			}
			if _, err := b.NewPending(t.Context(), "next.example"); err == nil {
				t.Fatal("checkpoint failure created replacement keys")
			}
			after, _, err := b.files.Read(certificateFilename(b.planJSON), maxCertificateFileBytes)
			if err != nil || !bytes.Equal(material, after) {
				t.Fatal("rejected checkpoint changed private material", err)
			}
		})
	}
}
