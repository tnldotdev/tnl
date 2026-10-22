package oidcauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
)

// AdmissionRule is operator-owned mapping from a verified direct OIDC identity
// to one configured company source. claims never assign a role or merge accounts.
type AdmissionRule struct {
	Team     string          `json:"team"`
	SourceID string          `json:"source_id"`
	Subjects []string        `json:"subjects"`
	Claim    *AdmissionClaim `json:"claim,omitempty"`
}
type AdmissionClaim struct {
	Name  AdmissionClaimName `json:"name"`
	Value string             `json:"value"`
}
type AdmissionClaimName string

const (
	TenantClaim       AdmissionClaimName = "tid"
	HostedDomainClaim AdmissionClaimName = "hd"
	GroupClaim        AdmissionClaimName = "groups"
)

func LoadAdmissions(path string) ([]AdmissionRule, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 64<<10 {
		return nil, errors.New("OIDC admission document exceeds size limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var rules []AdmissionRule
	if err := d.Decode(&rules); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF || len(rules) > 64 {
		return nil, errors.New("invalid OIDC admission document")
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if !validClaim(r.Team, 63) || !validClaim(r.SourceID, 256) || seen[r.Team] || len(r.Subjects) > 1024 || len(r.Subjects) == 0 && r.Claim == nil {
			return nil, errors.New("invalid OIDC admission rule")
		}
		seen[r.Team] = true
		for _, subject := range r.Subjects {
			if !validClaim(subject, 256) {
				return nil, errors.New("invalid OIDC admission subject")
			}
		}
		if r.Claim != nil && (!validClaim(r.Claim.Value, 256) || r.Claim.Name != TenantClaim && r.Claim.Name != HostedDomainClaim && r.Claim.Name != GroupClaim) {
			return nil, errors.New("invalid OIDC admission claim")
		}
	}
	return rules, nil
}
func (r AdmissionRule) Allows(i Identity) bool {
	if slices.Contains(r.Subjects, i.Subject) {
		return true
	}
	if r.Claim == nil {
		return false
	}
	switch r.Claim.Name {
	case TenantClaim:
		return i.TenantID == r.Claim.Value
	case HostedDomainClaim:
		return i.HostedDomain == r.Claim.Value
	case GroupClaim:
		return slices.Contains(i.Groups, r.Claim.Value)
	}
	return false
}
