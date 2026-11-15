package httpprotection

import (
	"io"
	"strings"
	"testing"

	policy "github.com/tnldotdev/tnl/internal/policy/httpprotection"
)

func TestMemoryMultipartRejectsAmbiguousAndTruncatedParts(t *testing.T) {
	for _, mode := range []policy.Mode{policy.Block, policy.Detect} {
		p := inspector(t, policy.Settings{WAF: mode})
		for _, disposition := range []string{
			`form-data; name="file"; filename="safe"; filename*=utf-8''attack`,
			`form-data; name="file"; filename*0="attack"`,
			`form-data; name="q"; name="q"`,
			`form-data; name="file"; filename="safe"; filename="other"`,
			`form-data; name="q"` + "\r\nContent-Transfer-Encoding: base64",
			`form-data; name="q"` + "\r\nContent-Disposition: form-data; name=other",
		} {
			data := "--tnl-boundary\r\nContent-Disposition: " + disposition + "\r\n\r\nvalue\r\n--tnl-boundary--\r\n"
			_, cleanup, result := p.Inspect(request("POST", "/", "multipart/form-data; boundary=tnl-boundary", data))
			cleanup()
			if result.Status != 400 {
				t.Fatal("ambiguous multipart reached the application", mode, disposition, result)
			}
		}
		_, cleanup, result := p.Inspect(request("POST", "/", "multipart/form-data; boundary=tnl-boundary",
			"--tnl-boundary\r\nContent-Disposition: form-data; name=q\r\n\r\ntruncated"))
		cleanup()
		if result.Status != 400 {
			t.Fatal("truncated multipart reached the application", mode, result)
		}
	}
}

func TestMemoryMultipartInspectsFieldsAndPreservesBytes(t *testing.T) {
	for _, mode := range []policy.Mode{policy.Block, policy.Detect} {
		p := inspector(t, policy.Settings{WAF: mode})
		data := "--tnl-boundary\r\nContent-Disposition: form-data; name=q\r\n\r\n<script>alert(1)</script>\r\n--tnl-boundary--\r\n"
		r, cleanup, result := p.Inspect(request("POST", "/", "multipart/form-data; boundary=tnl-boundary", data))
		defer cleanup()
		if mode == policy.Block {
			if result.Status != 403 {
				t.Fatal("multipart field escaped inspection", result)
			}
		} else {
			if result.Status != 0 || len(result.RuleIDs) == 0 {
				t.Fatal("detection lost multipart matches", result)
			}
			forwarded, err := io.ReadAll(r.Body)
			if err != nil || string(forwarded) != data {
				t.Fatal("multipart forwarding changed bytes", err)
			}
		}
	}
}

func TestMemoryMultipartEnforcesFieldBudget(t *testing.T) {
	p := inspector(t, policy.Settings{})
	data := strings.Repeat("--tnl-boundary\r\nContent-Disposition: form-data; name=q\r\n\r\nx\r\n", 1001) + "--tnl-boundary--\r\n"
	_, cleanup, result := p.Inspect(request("POST", "/", "multipart/form-data; boundary=tnl-boundary", data))
	defer cleanup()
	if result.Status != 400 && result.Status != 413 {
		t.Fatal("multipart exceeded the argument budget", result)
	}
}
