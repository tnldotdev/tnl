package clientstate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type HostnameSelection struct {
	RequestKey string `json:"request_key"`
	ClaimID    string `json:"claim_id,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
}

// Selection and release state use whole-map updates; callers serialize read-modify-write sequences.
type hostnameSelectionsFile struct {
	Version    int                          `json:"version"`
	Selections map[string]HostnameSelection `json:"selections"`
}

type hostnameReleasesFile struct {
	Version  int               `json:"version"`
	Releases map[string]string `json:"releases"`
}

func (s *Store) HostnameSelection(target string) (HostnameSelection, bool, error) {
	stored, found, err := s.readHostnameSelections()
	if err != nil || !found {
		return HostnameSelection{}, false, err
	}
	selection, found := stored.Selections[target]
	return selection, found, nil
}

func (s *Store) SaveHostnameSelection(target string, selection HostnameSelection) error {
	if strings.TrimSpace(target) == "" || strings.TrimSpace(selection.RequestKey) == "" || len(selection.RequestKey) > 128 {
		return errors.New("clientstate: invalid hostname selection")
	}
	stored, found, err := s.readHostnameSelections()
	if err != nil {
		return err
	}
	if !found {
		stored = hostnameSelectionsFile{Version: stateVersion, Selections: make(map[string]HostnameSelection)}
	}
	if len(stored.Selections) >= 128 {
		if _, exists := stored.Selections[target]; !exists {
			return errors.New("clientstate: too many hostname selections")
		}
	}
	stored.Selections[target] = selection
	return writeJSON(s.selectionsPath, stored)
}

func (s *Store) RemoveHostnameSelection(hostname string) error {
	stored, found, err := s.readHostnameSelections()
	if err != nil || !found {
		return err
	}
	for target, selection := range stored.Selections {
		if selection.Hostname == hostname {
			delete(stored.Selections, target)
		}
	}
	if len(stored.Selections) == 0 {
		if err := os.Remove(s.selectionsPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDir(filepath.Dir(s.selectionsPath))
	}
	return writeJSON(s.selectionsPath, stored)
}

func (s *Store) PendingHostnameRelease(hostname string) (string, bool, error) {
	stored, found, err := s.readHostnameReleases()
	if err != nil || !found {
		return "", false, err
	}
	claimID, found := stored.Releases[hostname]
	return claimID, found, nil
}

func (s *Store) SaveHostnameRelease(hostname, claimID string) error {
	if strings.TrimSpace(hostname) != hostname || hostname == "" || len(hostname) > 253 ||
		strings.TrimSpace(claimID) != claimID || claimID == "" || len(claimID) > 64 {
		return errors.New("clientstate: invalid hostname release")
	}
	stored, found, err := s.readHostnameReleases()
	if err != nil {
		return err
	}
	if !found {
		stored = hostnameReleasesFile{Version: stateVersion, Releases: make(map[string]string)}
	}
	if len(stored.Releases) >= 128 {
		if _, exists := stored.Releases[hostname]; !exists {
			return errors.New("clientstate: too many hostname releases")
		}
	}
	stored.Releases[hostname] = claimID
	return writeJSON(s.releasesPath, stored)
}

func (s *Store) ClearHostnameRelease(hostname string) error {
	stored, found, err := s.readHostnameReleases()
	if err != nil || !found {
		return err
	}
	delete(stored.Releases, hostname)
	if len(stored.Releases) == 0 {
		if err := os.Remove(s.releasesPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDir(filepath.Dir(s.releasesPath))
	}
	return writeJSON(s.releasesPath, stored)
}

func (s *Store) readHostnameSelections() (hostnameSelectionsFile, bool, error) {
	var stored hostnameSelectionsFile
	found, err := readJSON(s.selectionsPath, &stored)
	if err != nil || !found {
		return hostnameSelectionsFile{}, found, err
	}
	if stored.Version != stateVersion || stored.Selections == nil || len(stored.Selections) > 128 {
		return hostnameSelectionsFile{}, true, errors.New("clientstate: hostname selections are invalid")
	}
	for target, selection := range stored.Selections {
		if strings.TrimSpace(target) == "" || strings.TrimSpace(selection.RequestKey) == "" || len(selection.RequestKey) > 128 {
			return hostnameSelectionsFile{}, true, errors.New("clientstate: hostname selections are invalid")
		}
	}
	return stored, true, nil
}

func (s *Store) readHostnameReleases() (hostnameReleasesFile, bool, error) {
	var stored hostnameReleasesFile
	found, err := readJSON(s.releasesPath, &stored)
	if err != nil || !found {
		return hostnameReleasesFile{}, found, err
	}
	if stored.Version != stateVersion || stored.Releases == nil || len(stored.Releases) > 128 {
		return hostnameReleasesFile{}, true, errors.New("clientstate: hostname releases are invalid")
	}
	for hostname, claimID := range stored.Releases {
		if strings.TrimSpace(hostname) != hostname || hostname == "" || len(hostname) > 253 ||
			strings.TrimSpace(claimID) != claimID || claimID == "" || len(claimID) > 64 {
			return hostnameReleasesFile{}, true, errors.New("clientstate: hostname releases are invalid")
		}
	}
	return stored, true, nil
}
