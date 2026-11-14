// package httpprotection owns validated HTTP inspection settings shared by
// project configuration, control, and publishers. it starts no workers.
package httpprotection

import (
	"errors"
	"io/fs"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
)

const (
	DefaultBodyBytes = 1 << 20
	MaxBodyBytes     = 2 << 20
	Ruleset          = "OWASP_CRS/4.25.0 tnl/1"
)

type Mode string

const (
	Block  Mode = "block"
	Detect Mode = "detect"
	Off    Mode = "off"
)

// Settings uses zero values for default blocking and the default body ceiling.
type Settings struct {
	WAF             Mode        `json:"waf,omitempty" yaml:"waf,omitempty" jsonschema:"enum=block,enum=detect,enum=off"`
	TemporaryBlocks bool        `json:"temporary_blocks,omitempty" yaml:"temporary_blocks,omitempty"`
	Challenge       Challenge   `json:"challenge,omitempty" yaml:"challenge,omitempty"`
	MaxBodyBytes    *int        `json:"max_body_bytes,omitempty" yaml:"max_body_bytes,omitempty" jsonschema:"minimum=1,maximum=2097152"`
	Exclusions      []Exclusion `json:"exclusions,omitempty" yaml:"exclusions,omitempty" jsonschema:"maxItems=32"`
}

func (s Settings) BlocksSources() bool {
	return s.TemporaryBlocks && (s.WAF == "" || s.WAF == Block)
}

type Exclusion struct {
	RuleID    int    `json:"rule_id" yaml:"rule_id" jsonschema:"required"`
	Path      string `json:"path" yaml:"path" jsonschema:"required"`
	Parameter string `json:"parameter,omitempty" yaml:"parameter,omitempty"`
}

func (s Settings) Defaults() Settings {
	if s.WAF == "" {
		s.WAF = Block
	}
	if s.MaxBodyBytes == nil {
		s.MaxBodyBytes = new(DefaultBodyBytes)
	}
	return s
}

var parameter = regexp.MustCompile(`^[a-zA-Z0-9_.\[\]-]{1,128}$`)

func (s Settings) Validate() error {
	s = s.Defaults()
	if s.Challenge != "" && s.Challenge != Turnstile {
		return errors.New("challenge must be turnstile or false")
	}
	if s.WAF != Block && s.WAF != Detect && s.WAF != Off {
		return errors.New("waf must be block, detect, or off")
	}
	if *s.MaxBodyBytes < 1 || *s.MaxBodyBytes > MaxBodyBytes {
		return errors.New("max_body_bytes must be between 1 and 2097152")
	}
	if len(s.Exclusions) > 32 {
		return errors.New("exclusions may contain at most 32 entries")
	}
	for _, e := range s.Exclusions {
		u, err := url.ParseRequestURI(e.Path)
		if err != nil || !strings.HasPrefix(e.Path, "/") || u.IsAbs() || u.Host != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.EscapedPath() != e.Path || len(e.Path) > 2048 || strings.HasPrefix(e.Path, "/__tnl/") {
			return errors.New("exclusion path must be an exact escaped application path without a query")
		}
		if !ruleIDs()[e.RuleID] {
			return errors.New("exclusion rule_id must name a bundled request rule")
		}
		if e.Parameter != "" && !parameter.MatchString(e.Parameter) {
			return errors.New("exclusion parameter must be a simple argument name of at most 128 bytes")
		}
	}
	return nil
}

// the pinned rules are the authority for exclusions, not an independently
// maintained list. only request detection rules may be excluded.
var ruleIDs = sync.OnceValue(func() map[int]bool {
	ids := make(map[int]bool)
	id := regexp.MustCompile(`\bid:\s*['"]?([0-9]+)`)
	_ = fs.WalkDir(coreruleset.FS, "@owasp_crs", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".conf") || !strings.Contains(path, "/REQUEST-9") || strings.Contains(path, "REQUEST-901-") || strings.Contains(path, "REQUEST-949-") {
			return err
		}
		data, err := fs.ReadFile(coreruleset.FS, path)
		if err != nil {
			return err
		}
		for _, match := range id.FindAllSubmatch(data, -1) {
			n, _ := strconv.Atoi(string(match[1]))
			ids[n] = true
		}
		return nil
	})
	return ids
})
