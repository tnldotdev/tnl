package clioutput

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/quick"
)

type commandAs struct{ value *commandError }

func (commandAs) Error() string { return "custom command error" }
func (e commandAs) As(target any) bool {
	if out, ok := target.(**commandError); ok {
		*out = e.value
		return true
	}
	return false
}

func TestCommandExtractionContracts(t *testing.T) {
	cause := errors.New("private cause")
	first := &commandError{command: CommandTitle("tnl", "inspect show <id>"), err: cause}
	for _, err := range []error{first, fmt.Errorf("outer: %w", first), errors.Join(first, WrapCommand("tnl publish", cause)), commandAs{first}} {
		if command, ok := CommandOf(err); !ok || command != "tnl inspect show" {
			t.Fatalf("command context = %q, %t", command, ok)
		}
	}
	if !errors.Is(WrapCommand(first.command, cause), cause) || WrapCommand(first.command, nil) != nil {
		t.Fatal("command wrapping changed cause identity")
	}
	for _, err := range []error{nil, cause, (*commandError)(nil), commandAs{}} {
		if command, ok := CommandOf(err); ok || command != "" {
			t.Fatalf("absent command context = %q, %t", command, ok)
		}
	}
}

func TestCopyableLines(t *testing.T) {
	url := "https://control.example.test/v1/auth/device/approve?code=ABCDEF-123456"
	path := "/var/data/my project/" + strings.Repeat("long-path/", 8) + "client.pem"
	command := "tnl connect orders --server=https://control.example.test -- 'two words'"
	for _, width := range []int{0, 1, 20, 40, 64, 72, 160} {
		for _, tc := range []struct {
			block Block
			value string
		}{
			{Text("Visit " + url), url},
			{Fields(Field{Label: "help", Value: url}), url},
			{Fields(Field{Label: "CA file", Value: path}), path},
			{Section("client command", Literal(command)), command},
			{Table([]string{"NAME", "ADDRESS"}, [][]string{{"web", url}}, "No services."), url},
			{Line(command), command},
		} {
			result := Message{Blocks: []Block{tc.block}}
			got, err := render(result, width)
			if err != nil || !strings.Contains(got, tc.value) {
				t.Fatalf("width %d: missing literal %q:\n%s\n%v", width, tc.value, got, err)
			}
			if width == 0 {
				var buf bytes.Buffer
				if err := Write(&buf, result); err != nil || buf.String() != got {
					t.Fatalf("redirected output: %q, %v", &buf, err)
				}
			}
		}
	}
}

func TestPlainOutput(t *testing.T) {
	var out bytes.Buffer
	results := []Block{
		Table([]string{"SERVICE", "STATE"}, nil, "No services."),
		Table([]string{"SERVICE", "STATE"}, [][]string{{"accounts", "ready"}, {"web", "not registered"}}, ""),
		Section("Open this URL", Literal("https://example.test")),
		Line("Signed in."),
	}
	for _, block := range results {
		if err := Write(&out, Message{Blocks: []Block{block}}); err != nil {
			t.Fatal(err)
		}
	}
	want := "No services.\nSERVICE   STATE\naccounts  ready\nweb       not registered\nOpen this URL:\nhttps://example.test\nSigned in.\n"
	if out.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", &out, want)
	}
	if got, _ := render(Message{Blocks: []Block{Text("two short words")}}, 9); got != "two short\nwords\n" {
		t.Fatalf("wrapped prose: %q", got)
	}
	if _, err := Render(Message{Blocks: []Block{Section("nested", nil)}}); err == nil {
		t.Fatal("accepted a missing block")
	}
}

func TestWriteErrors(t *testing.T) {
	result := Message{Blocks: []Block{Text("ready")}}
	if err := Write(shortWriter{}, result); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
	want := errors.New("write failed")
	if err := Write(errorWriter{want}, result); !errors.Is(err, want) {
		t.Fatalf("writer error: %v", err)
	}
}

func safeOutput(value string, width int) bool {
	got, err := render(Message{Blocks: []Block{
		Text(value), Line(value), Fields(Field{Label: value, Value: value}),
		Section(value, Literal(value)), Table([]string{"VALUE"}, [][]string{{value}}, ""),
	}}, width)
	return err == nil && strings.IndexFunc(got, func(r rune) bool { return r != '\n' && (r < 0x20 || r > 0x7e) }) == -1
}

func TestRenderArbitraryBytes(t *testing.T) {
	if err := quick.Check(func(input []byte) bool { return safeOutput(string(input), 80) }, &quick.Config{MaxCount: 5_000}); err != nil {
		t.Fatal(err)
	}
	got, err := Render(Message{Blocks: []Block{Line("caf\u00e9\r\n\x1b[31m\xff")}})
	if err != nil || got != `caf\u00e9\x0d\x0a\x1b[31m\xff`+"\n" {
		t.Fatalf("escaped output: %q, %v", got, err)
	}
}

func FuzzRender(f *testing.F) {
	for index, seed := range [][]byte{nil, []byte("\x00\x1b\r\n\t"), []byte("caf\u00e9 \U0001f680"), {0xff, 0xfe}, bytes.Repeat([]byte("long value "), 2000)} {
		f.Add(seed, uint8(index))
	}
	f.Fuzz(func(t *testing.T, input []byte, width uint8) {
		if !safeOutput(string(input), int(width)) {
			t.Fatal("unsafe output")
		}
	})
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(value []byte) (int, error) { return len(value) / 2, nil }
