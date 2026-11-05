package runtimetrace

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestProtocolBoundsAndValidation(t *testing.T) {
	valid := Command{ID: 1, Kind: Arm, Phase: "connect-postgres-warm", Component: "visitor-1", Start: time.Now(), Duration: time.Second}
	for _, c := range []Command{valid, {ID: 2, Kind: Trigger, Event: &Event{Slot: 17108, Kind: "query", Started: time.Second, Completed: 2 * time.Second, Observed: 2 * time.Second}}, {ID: 3, Kind: Export}} {
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		if err := WriteFrame(&b, c); err != nil || b.Len() > MaxFrameBytes {
			t.Fatalf("encode: %v size=%d", err, b.Len())
		}
		var got Command
		if err := NewDecoder(&b).Read(&got); err != nil || got.Kind != c.Kind {
			t.Fatalf("decode: %+v %v", got, err)
		}
	}
	for _, change := range []func(*Command){func(c *Command) { c.ID = 0 }, func(c *Command) { c.ID = MaxCommands + 1 }, func(c *Command) { c.Kind = "secret SQL" }, func(c *Command) { c.Phase = "../phase" }, func(c *Command) { c.Duration = 5*time.Minute + 1 }, func(c *Command) { c.Start = time.Time{} }, func(c *Command) { c.Event = &Event{} }} {
		c := valid
		change(&c)
		if c.Validate() == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	for _, c := range []Command{{ID: 1, Kind: Trigger}, {ID: 1, Kind: Trigger, Event: &Event{Kind: "SQL"}}, {ID: 1, Kind: Trigger, Event: &Event{Kind: "query", Slot: -1}}, {ID: 1, Kind: Trigger, Event: &Event{Kind: "query", Started: time.Second}}, {ID: 1, Kind: Export, Event: &Event{}}, {ID: 1, Kind: Export, Phase: "phase"}} {
		if c.Validate() == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	for _, text := range []string{strings.Repeat("x", MaxFrameBytes+1), `{"ID":1,"Kind":"EXPORT","SQL":"do not retain"}`, "{} {}", "null null"} {
		var c Command
		err := NewDecoder(strings.NewReader(text + "\n")).Read(&c)
		if err == nil || strings.Contains(err.Error(), "do not retain") {
			t.Fatalf("invalid frame: %v", err)
		}
	}
	if err := NewDecoder(strings.NewReader("")).Read(new(Command)); err != io.EOF {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if WriteFrame(&b, strings.Repeat("x", MaxFrameBytes)) == nil || b.Len() != 0 {
		t.Fatal("oversized write emitted bytes")
	}
	w := &boundedWriter{data: make([]byte, 5)}
	if n, err := w.Write([]byte("123456")); n != 5 || err == nil || w.used != 5 {
		t.Fatalf("bounded writer: n=%d err=%v used=%d", n, err, w.used)
	}
	// even four maximum-name commands from this encoder fit a 4KiB pipe;
	// TRIGGER therefore never needs the child to finish its hold to make room.
	b.Reset()
	for id := 1; id <= MaxCommands; id++ {
		c := Command{ID: id, Kind: Arm, Phase: strings.Repeat("p", 80), Component: strings.Repeat("c", 80), Start: time.Now(), Duration: 5 * time.Minute}
		if err := WriteFrame(&b, c); err != nil {
			t.Fatal(err)
		}
	}
	if b.Len() > 4096 {
		t.Fatalf("commands exceed minimum pipe size: %d", b.Len())
	}
}

func TestConsumeArgs(t *testing.T) {
	plain := []string{"tnl", "--no-config", "version"}
	remaining, _, enabled, err := ConsumeArgs(plain)
	if err != nil || enabled || strings.Join(remaining, " ") != strings.Join(plain, " ") {
		t.Fatalf("plain arguments changed: %v %v %v", remaining, enabled, err)
	}
	private := []string{CommandFDFlag + "=3", ReplyFDFlag + "=4", DirectoryFlag + "=/results/native-late-phase-visitor-1"}
	remaining, directory, enabled, err := ConsumeArgs(append(append([]string{}, plain...), private...))
	if err != nil || !enabled || directory != "/results/native-late-phase-visitor-1" || strings.Join(remaining, " ") != strings.Join(plain, " ") {
		t.Fatalf("private arguments: %v %s %v %v", remaining, directory, enabled, err)
	}
	for _, args := range [][]string{{CommandFDFlag + "=3"}, {CommandFDFlag, "3"}, {CommandFDFlag + "=4", private[1], private[2]}, {private[0], private[1], DirectoryFlag + "=relative"}, {private[0], private[1], DirectoryFlag + "=/"}, {private[0], private[1], private[2], private[2]}} {
		if _, _, _, err := ConsumeArgs(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
