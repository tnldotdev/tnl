package clioutput

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"testing/quick"
)

func TestRenderFrame(t *testing.T) {
	got, err := Render(Frame{
		Command: "tnl dev",
		State:   "ready",
		Blocks: []Block{
			Fields(Field{Label: "framework", Value: "vite"}),
			Flow(
				FlowNode{Label: "https://chase.tnl.dev"},
				FlowNode{Label: "tnl"},
				FlowNode{Label: "http://127.0.0.1:5173"},
			),
		},
		Footer: "ctrl+c to stop",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "+--[ tnl dev ]-- ready ----------------------------------------+\n" +
		"|                                                              |\n" +
		"|  framework  vite                                             |\n" +
		"|                                                              |\n" +
		"|  https://chase.tnl.dev                                       |\n" +
		"|     |                                                        |\n" +
		"|     v                                                        |\n" +
		"|  tnl                                                         |\n" +
		"|     |                                                        |\n" +
		"|     v                                                        |\n" +
		"|  http://127.0.0.1:5173                                       |\n" +
		"|                                                              |\n" +
		"+-- ctrl+c to stop --------------------------------------------+\n"
	if got != want {
		t.Fatalf("frame =\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderSectionsTreeAndFailure(t *testing.T) {
	got, err := Render(Frame{
		Command: "tnl status",
		State:   "1 local tunnel",
		Blocks: []Block{Section("ready",
			Tree(TreeNode{Label: "route", Children: []TreeNode{
				{Label: "hostname", Value: "route.example"},
				{Label: "state", Value: "ready"},
			}}),
			Flow(FlowNode{Label: "publisher", Detail: "connection refused", Failure: true}, FlowNode{Label: "local service"}),
		)},
		Footer: "TNL_TARGET_UNAVAILABLE",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"|-- ready ",
		"|  route",
		"|  |-- hostname  route.example",
		"|  `-- state  ready",
		"|     x  connection refused",
		"+-- TNL_TARGET_UNAVAILABLE ",
	} {
		if !strings.Contains(got, fragment) {
			t.Fatalf("frame does not contain %q:\n%s", fragment, got)
		}
	}
}

func TestRenderWrapsAndEscapesWithoutExceedingLimit(t *testing.T) {
	got, err := Render(Frame{
		Command: "tnl route list",
		State:   "routes",
		Blocks: []Block{Fields(
			Field{Label: "hostname", Value: strings.Repeat("a", 100) + ".example"},
			Field{Label: "name", Value: "caf\u00e9\x1b[31m"},
		)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `caf\u00e9\x1b[31m`) {
		t.Fatalf("escaped frame = %q", got)
	}
	assertFrameInvariants(t, got)
}

func TestRenderPreservesLongUniqueValueAcrossWrapping(t *testing.T) {
	var value strings.Builder
	for index := range 80 {
		fmt.Fprintf(&value, "%03dabcdef", index)
	}
	for name, block := range map[string]Block{
		"text":  Text(value.String()),
		"field": Fields(Field{Label: "hostname", Value: value.String()}),
		"flow":  Flow(FlowNode{Label: value.String()}),
		"tree":  Tree(TreeNode{Label: "hostname", Value: value.String()}),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Render(Frame{Command: "tnl status", State: "result", Blocks: []Block{block}})
			if err != nil {
				t.Fatal(err)
			}
			assertFrameInvariants(t, got)
			var unwrapped strings.Builder
			for _, line := range strings.Split(got, "\n") {
				if strings.HasPrefix(line, "|") {
					unwrapped.WriteString(strings.TrimSpace(strings.Trim(line, "|")))
				}
			}
			if !strings.Contains(unwrapped.String(), value.String()) {
				t.Fatalf("wrapped %s lost or reordered value bytes:\n%s", name, got)
			}
		})
	}
}

func TestRenderRightBorderIsAligned(t *testing.T) {
	tests := map[string]Frame{
		"dev output": {
			Command: "tnl dev",
			State:   "ready",
			Blocks: []Block{
				Fields(Field{Label: "framework", Value: "vite"}),
				Flow(
					FlowNode{Label: "https://chase.tnl.dev"},
					FlowNode{Label: "tnl"},
					FlowNode{Label: "http://127.0.0.1:5173"},
				),
			},
			Footer: "ctrl+c to stop",
		},
		"every block with wrapping": {
			Command: "tnl status",
			State:   "results",
			Blocks: []Block{
				Text("long text " + strings.Repeat("word ", 30)),
				Fields(Field{Label: "escaped", Value: "tab\t caf\x11"}),
				Flow(FlowNode{Label: strings.Repeat("publisher-", 10), Detail: strings.Repeat("failure ", 20), Failure: true}, FlowNode{Label: "local service"}),
				Transition("old state", strings.Repeat("changing ", 20), "new state"),
				Tree(TreeNode{Label: "route", Children: []TreeNode{{Label: "hostname", Value: strings.Repeat("a", 100)}}}),
				Section(strings.Repeat("section ", 20), Fields(Field{Label: "state", Value: "ready"})),
			},
			Footer: "complete",
		},
		"maximum width": {
			Command: "tnl",
			State:   strings.Repeat("s", maxWidth-len("+--[ tnl ]-- ")-3),
			Blocks:  []Block{Text(strings.Repeat("x", 200))},
		},
	}
	for name, frame := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Render(frame)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
			borderColumn := len(lines[0]) - 1
			for index, line := range lines {
				if len(line) != borderColumn+1 {
					t.Fatalf("line %d right border is in column %d, want %d:\n%s", index+1, len(line)-1, borderColumn, got)
				}
				want := byte('|')
				if index == 0 || index == len(lines)-1 {
					want = '+'
				}
				if line[borderColumn] != want {
					t.Fatalf("line %d has %q in right-border column %d, want %q:\n%s", index+1, line[borderColumn], borderColumn, want, got)
				}
			}
		})
	}
}

func TestRenderRejectsInvalidRails(t *testing.T) {
	for _, frame := range []Frame{
		{},
		{Command: "tnl", State: "bad\nstate"},
		{Command: strings.Repeat("x", 80), State: "failed"},
		{Command: "tnl", State: "failed", Blocks: []Block{Section("nested", nil)}},
	} {
		if _, err := Render(frame); err == nil {
			t.Fatalf("Render(%#v) succeeded", frame)
		}
	}
}

func TestCommandContext(t *testing.T) {
	if got := CommandTitle("tnl", "team member set-role <membership-id>"); got != "tnl team member set-role" {
		t.Fatalf("CommandTitle() = %q", got)
	}
	want := errors.New("failed")
	err := WrapCommand("tnl status", want)
	if !errors.Is(err, want) {
		t.Fatal("command context did not preserve its cause")
	}
	if command, ok := CommandOf(err); !ok || command != "tnl status" {
		t.Fatalf("CommandOf() = %q, %t", command, ok)
	}
	if WrapCommand("tnl", nil) != nil {
		t.Fatal("WrapCommand returned an error for a nil cause")
	}
}

func TestWritePropagatesWriterError(t *testing.T) {
	want := errors.New("write failed")
	if err := Write(errorWriter{err: want}, Frame{Command: "tnl", State: "ready"}); !errors.Is(err, want) {
		t.Fatalf("Write error = %v", err)
	}
}

func TestWriteRejectsShortWrite(t *testing.T) {
	if err := Write(shortWriter{}, Frame{Command: "tnl", State: "ready"}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write error = %v", err)
	}
}

func TestRenderAcceptsMaximumRailAndRejectsLongerRail(t *testing.T) {
	prefixWithoutState := "+--[ tnl ]-- "
	state := strings.Repeat("s", maxWidth-len(prefixWithoutState)-3)
	got, err := Render(Frame{Command: "tnl", State: state})
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.SplitN(got, "\n", 2)[0]) != maxWidth {
		t.Fatalf("top rail width = %d", len(strings.SplitN(got, "\n", 2)[0]))
	}
	if _, err := Render(Frame{Command: "tnl", State: state + "s"}); err == nil {
		t.Fatal("rail wider than the limit was accepted")
	}
}

func TestRenderPathologicalDynamicContent(t *testing.T) {
	values := []string{
		"",
		" ",
		strings.Repeat("x", 10_000),
		strings.Repeat("word ", 2_000),
		"\x00\x01\x02\x1b\x7f",
		"line one\r\nline two\tend",
		"caf\u00e9 \u4e16\u754c \U0001f680",
		string([]byte{0xff, 0xfe, 'x', 0xc0, 0xaf}),
	}
	for index, value := range values {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			got, err := Render(Frame{
				Command: "tnl status",
				State:   "result",
				Blocks: []Block{
					Text(value),
					Fields(Field{Label: strings.Repeat("label", 20), Value: value}),
					Section(value, Flow(
						FlowNode{Label: value, Detail: value, Failure: true},
						FlowNode{Label: value},
					)),
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			assertFrameInvariants(t, got)
		})
	}
}

func TestRenderDeepTree(t *testing.T) {
	root := TreeNode{Label: "root"}
	current := &root
	for depth := 0; depth < 1_000; depth++ {
		current.Children = []TreeNode{{Label: strings.Repeat("node", depth%30+1), Value: strings.Repeat("value", depth%20+1)}}
		current = &current.Children[0]
	}
	got, err := Render(Frame{Command: "tnl status", State: "ready", Blocks: []Block{Tree(root)}})
	if err != nil {
		t.Fatal(err)
	}
	assertFrameInvariants(t, got)
}

func TestRenderManySections(t *testing.T) {
	blocks := make([]Block, 2_000)
	for index := range blocks {
		blocks[index] = Section(fmt.Sprintf("section %d", index), Fields(
			Field{Label: "index", Value: strconv.Itoa(index)},
		))
	}
	got, err := Render(Frame{Command: "tnl status", State: "many results", Blocks: blocks})
	if err != nil {
		t.Fatal(err)
	}
	assertFrameInvariants(t, got)
}

func TestRenderArbitraryBytes(t *testing.T) {
	property := func(input []byte) bool {
		value := string(input)
		got, err := Render(Frame{
			Command: "tnl",
			State:   "result",
			Blocks: []Block{
				Text(value),
				Fields(Field{Label: value, Value: value}),
				Flow(FlowNode{Label: value, Detail: value}, FlowNode{Label: value}),
			},
		})
		return err == nil && frameInvariants(got) == nil
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 5_000}); err != nil {
		t.Fatal(err)
	}
}

func FuzzRender(f *testing.F) {
	for index, seed := range [][]byte{
		nil,
		[]byte("hello world"),
		[]byte("\x00\x1b\r\n\t"),
		[]byte("caf\u00e9 \U0001f680"),
		{0xff, 0xfe, 0xc0, 0xaf},
		bytes.Repeat([]byte("long-value-"), 100),
	} {
		f.Add(seed, uint8(index))
	}
	f.Fuzz(func(t *testing.T, input []byte, widthOffset uint8) {
		value := string(input)
		got, err := Render(Frame{
			Command: "tnl dev",
			State:   "result",
			Blocks: []Block{
				Text(value),
				Fields(Field{Label: value, Value: value}),
				Section(value, Tree(TreeNode{Label: value, Children: []TreeNode{{Label: value, Value: value}}})),
				Flow(FlowNode{Label: value, Detail: value, Failure: true}, FlowNode{Label: value}),
				Transition(value, value, value),
			},
			Footer: strings.Repeat("f", 57+int(widthOffset%9)),
		})
		if err != nil {
			t.Fatal(err)
		}
		assertFrameInvariants(t, got)
	})
}

func assertFrameInvariants(t *testing.T, frame string) {
	t.Helper()
	if err := frameInvariants(frame); err != nil {
		t.Fatal(err)
	}
}

func frameInvariants(frame string) error {
	if !strings.HasSuffix(frame, "\n") || strings.HasSuffix(frame, "\n\n") {
		return fmt.Errorf("frame has invalid trailing newline: %q", frame)
	}
	lines := strings.Split(strings.TrimSuffix(frame, "\n"), "\n")
	if len(lines) < 3 {
		return fmt.Errorf("frame has only %d lines", len(lines))
	}
	width := len(lines[0])
	if width < defaultWidth || width > maxWidth {
		return fmt.Errorf("frame width = %d", width)
	}
	for index, line := range lines {
		if len(line) != width {
			return fmt.Errorf("line %d width = %d, want %d: %q", index, len(line), width, line)
		}
		for _, character := range line {
			if character < 0x20 || character > 0x7e {
				return fmt.Errorf("line %d is not ASCII: %q", index, line)
			}
		}
	}
	if lines[0][0] != '+' || lines[0][width-1] != '+' || lines[len(lines)-1][0] != '+' || lines[len(lines)-1][width-1] != '+' {
		return errors.New("frame rails do not have corners")
	}
	for index, line := range lines[1 : len(lines)-1] {
		if line[0] != '|' || line[width-1] != '|' {
			return fmt.Errorf("body line %d does not have sides: %q", index+1, line)
		}
	}
	return nil
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(value []byte) (int, error) { return len(value) / 2, nil }
