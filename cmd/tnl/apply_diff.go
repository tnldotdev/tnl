package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/clioutput"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type applyChange struct {
	Resource string          `json:"resource"`
	Name     string          `json:"name,omitempty"`
	Field    string          `json:"field"`
	Before   json.RawMessage `json:"before"`
	After    json.RawMessage `json:"after"`
}
type applyDiff struct {
	Team       string        `json:"team_id"`
	Deployment string        `json:"deployment"`
	Base       int64         `json:"base_revision,string"`
	Changes    []applyChange `json:"changes"`
}

type applyField struct{ resource, name, field string }
type applyFacts map[applyField]json.RawMessage

func compareApply(team authorityv1.Team, deployment string, saved controlv1.AppliedProjectConfiguration, desired controlv1.ProjectConfiguration, services controlv1.ProjectServiceDeclarations) (applyDiff, error) {
	result := applyDiff{team.Id, deployment, saved.Revision, []applyChange{}}
	before, err := declarationFacts(saved.Configuration, saved.ServiceDeclarations, "")
	if err != nil {
		return result, err
	}
	// control captures the deployment domain on first apply. an omitted
	// selector reuses that domain even if the team's default has since changed.
	domain := team.DefaultDomainId
	if saved.Deployments != nil {
		for _, d := range *saved.Deployments {
			if d.Name == deployment && d.DomainId != "" {
				domain = d.DomainId
				break
			}
		}
	}
	after, err := declarationFacts(desired, services, domain)
	if err != nil {
		return result, err
	}
	if saved.Revision == 0 || saved.RetiredAt != nil {
		after[applyField{"deployment", deployment, "state"}] = json.RawMessage(`"active"`)
		if saved.RetiredAt != nil {
			before[applyField{"deployment", deployment, "state"}] = json.RawMessage(`"retired"`)
		}
	}
	keys := maps.Clone(before)
	maps.Copy(keys, after)
	for key := range keys {
		if !bytes.Equal(before[key], after[key]) {
			result.Changes = append(result.Changes, applyChange{key.resource, key.name, key.field, before[key], after[key]})
		}
	}
	slices.SortFunc(result.Changes, func(a, b applyChange) int {
		if c := strings.Compare(a.Resource, b.Resource); c != 0 {
			return c
		}
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Field, b.Field)
	})
	return result, nil
}

// compare the declared fields, never the allocated endpoints or live publisher
// status. use the saved wire representation for fields without special display.
func declarationFacts(c controlv1.ProjectConfiguration, declarations controlv1.ProjectServiceDeclarations, fallbackDomain string) (applyFacts, error) {
	facts := applyFacts{}
	fields := func(resource, name string, v any) error {
		data, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(data, &object); err != nil {
			return err
		}
		for field, value := range object {
			facts[applyField{resource, name, field}] = value
		}
		return nil
	}
	for name, protocol := range declarations {
		if err := fields("service", name, map[string]any{"declared protocol": protocol}); err != nil {
			return nil, err
		}
	}
	var domain *string
	if c.Settings != nil {
		settings := *c.Settings
		if settings.DomainId == nil && fallbackDomain != "" {
			settings.DomainId = &fallbackDomain
		}
		domain = settings.DomainId
		if err := fields("deployment", "", settings); err != nil {
			return nil, err
		}
	}
	for name, s := range c.Services {
		if s.DomainId == nil {
			s.DomainId = domain
		}
		reachability := "connector-only"
		if s.Public != nil && *s.Public {
			reachability = "public endpoint requested"
		}
		s.Public = nil
		if s.Ephemeral != nil && !*s.Ephemeral {
			s.Ephemeral = nil
		}
		if s.TargetTls != nil {
			t := *s.TargetTls
			if t.CaPem != nil {
				t.CaPem = new(fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(*t.CaPem))))
			}
			s.TargetTls = &t
		}
		if u, err := url.Parse(s.Target); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" {
			port := u.Port()
			if port == "" {
				port = "80"
				if u.Scheme == "https" {
					port = "443"
				}
			}
			s.Target = net.JoinHostPort(u.Hostname(), port)
		}
		if err := fields("binding", name, s); err != nil {
			return nil, err
		}
		if err := fields("binding", name, map[string]any{"reachability": reachability}); err != nil {
			return nil, err
		}
	}
	if c.Workloads != nil {
		for name, w := range *c.Workloads {
			w.Services = slices.Sorted(slices.Values(w.Services))
			if w.Github != nil {
				g := *w.Github
				g.Events = slices.Sorted(slices.Values(g.Events))
				w.Github = &g
				w.Trust = controlv1.WorkloadTrust{}
			}
			if err := fields("workload", name, w); err != nil {
				return nil, err
			}
		}
	}
	return facts, nil
}

func displayDiffValue(v json.RawMessage) string {
	if v == nil {
		return "(absent)"
	}
	var text string
	if json.Unmarshal(v, &text) == nil {
		return text
	}
	return string(v)
}
func (d applyDiff) write(out io.Writer, mode statusOutputMode) error {
	if mode == statusOutputJSON {
		return json.NewEncoder(out).Encode(d)
	}
	blocks := []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "team", Value: d.Team}, clioutput.Field{Label: "deployment", Value: d.Deployment}, clioutput.Field{Label: "base revision", Value: strconv.FormatInt(d.Base, 10)})}
	for _, c := range d.Changes {
		label := strings.ReplaceAll(c.Field, "_", " ")
		switch c.Field {
		case "services":
			label = "allowed services"
		case "target_tls":
			label = "target trust"
		case "access":
			label = "visitor access"
		}
		blocks = append(blocks, clioutput.Section(strings.TrimSpace(c.Resource+" "+c.Name), clioutput.Fields(clioutput.Field{Label: label, Value: displayDiffValue(c.Before) + " -> " + displayDiffValue(c.After)})))
	}
	state := "changes"
	if len(d.Changes) == 0 {
		state = "no changes"
	}
	return writeHumanFrame(out, "tnl apply", state, "compared with the saved revision; no changes applied", blocks...)
}
