package credentialfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

func TestGroupIdentityCurrentCatalogRequiresSelectionPin(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt"} {
		t.Run(mode, func(t *testing.T) {
			value := groupFixture(t)
			state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			profile, err := state.Server(t.Context(), value.ControlURL)
			if err != nil {
				t.Fatal(err)
			}
			if err := RetainGroup(t.Context(), profile, value); err != nil {
				t.Fatal(err)
			}
			directory, err := groupStateDirectory(profile, value.ControlURL)
			if err != nil {
				t.Fatal(err)
			}
			name := groupStateName(groupReference{Member: value.Member, Instance: value.Instance})
			before, _, err := directory.Read(name, maxGroupIdentityBytes)
			if err != nil {
				t.Fatal(err)
			}
			pin := groupPinName(value.Member.ProjectKey, value.Member.GroupId, value.Instance)
			if mode == "missing" {
				err = os.Remove(filepath.Join(directory.Path(), pin))
			} else {
				err = directory.Write(pin, []byte(`{"version":1,"reference":null}`))
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := SavedGroup(profile, value.ControlURL, value.Member.ProjectKey, value.Member.GroupId, value.Instance); !errors.Is(err, clientstate.ErrPublisherStateConflict) {
				t.Fatal("catalog supplied authority without its current pin", err)
			}
			if err := RetainGroup(t.Context(), profile, value); !errors.Is(err, clientstate.ErrPublisherStateConflict) {
				t.Fatal("retention imported an unpinned catalog entry", err)
			}
			if err := RetireGroup(t.Context(), profile, value); !errors.Is(err, clientstate.ErrPublisherStateConflict) {
				t.Fatal("retirement reconstructed a missing pin", err)
			}
			after, _, err := directory.Read(name, maxGroupIdentityBytes)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected catalog changed signing authority", err)
			}
		})
	}
}
