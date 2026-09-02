package workerv1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/transportv1"
)

func TestControlFramesAreStrictAndBounded(t *testing.T) {
	valid := []Message{
		{Type: Hello, Capacity: 500},
		{Type: Accepted},
		{Type: AttachRoute, Route: &RouteRef{RouteID: "route", Version: 2}, Endpoint: &transportv1.TailcatDescriptor{Version: 1, PublisherPublicKey: "nodekey:key", RelayRegion: "test"}, WorkerPrivateKey: "privkey:key"},
		{Type: RouteReady, Route: &RouteRef{RouteID: "route", Version: 2}},
		{Type: DetachRoute, Route: &RouteRef{RouteID: "route", Version: 2}},
		{Type: RouteDrained, Route: &RouteRef{RouteID: "route", Version: 2}},
		{Type: WorkerDraining},
		{Type: Error, Route: &RouteRef{RouteID: "route", Version: 2}, Code: StaleAssignment},
	}
	for _, message := range valid {
		var wire bytes.Buffer
		if err := WriteControl(&wire, message); err != nil {
			t.Fatalf("WriteControl(%s): %v", message.Type, err)
		}
		got, err := ReadControl(&wire)
		if err != nil || got.Type != message.Type {
			t.Fatalf("ReadControl(%s) = %#v, %v", message.Type, got, err)
		}
	}

	for name, payload := range map[string]string{
		"unknown field": `{"type":"accepted","extra":true}`,
		"unknown type":  `{"type":"future"}`,
		"invalid route": `{"type":"route_ready","route":{"route_id":"route","version":0}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var wire bytes.Buffer
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
			wire.Write(header[:])
			wire.WriteString(payload)
			if _, err := ReadControl(&wire); err == nil {
				t.Fatal("ReadControl succeeded")
			}
		})
	}

	var oversized bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], MaxControlBytes+1)
	oversized.Write(header[:])
	oversized.WriteString(strings.Repeat("x", MaxControlBytes+1))
	if _, err := ReadControl(&oversized); err == nil {
		t.Fatal("oversized frame succeeded")
	}
}

func TestControlSchemaTracksMessageTypes(t *testing.T) {
	type definition struct {
		Properties map[string]struct {
			Const string `json:"const"`
		} `json:"properties"`
	}
	var schema struct {
		OneOf []struct {
			Ref string `json:"$ref"`
		} `json:"oneOf"`
		Defs map[string]definition `json:"$defs"`
	}
	path := filepath.Join("..", "..", "..", "api", "worker", "v1", "control.schema.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, branch := range schema.OneOf {
		name := strings.TrimPrefix(branch.Ref, "#/$defs/")
		if name == branch.Ref || schema.Defs[name].Properties["type"].Const == "" {
			t.Fatalf("invalid schema branch %q", branch.Ref)
		}
		got = append(got, schema.Defs[name].Properties["type"].Const)
	}
	want := []string{
		string(Hello), string(Accepted), string(AttachRoute), string(RouteReady),
		string(DetachRoute), string(RouteDrained), string(WorkerDraining), string(Error),
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("schema message types = %v, want %v", got, want)
	}
	dataHeaderPath := filepath.Join("..", "..", "..", "api", "worker", "v1", "data-header.schema.json")
	data, err = os.ReadFile(dataHeaderPath)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatal("data header schema is not valid JSON")
	}
}

func FuzzReadFrames(f *testing.F) {
	controls := []Message{
		{Type: Hello, Capacity: 500},
		{Type: Accepted},
		{Type: AttachRoute, Route: &RouteRef{RouteID: "route", Version: 2}, Endpoint: &transportv1.TailcatDescriptor{Version: 1, PublisherPublicKey: "nodekey:key", RelayRegion: "test"}, WorkerPrivateKey: "privkey:key"},
		{Type: RouteReady, Route: &RouteRef{RouteID: "route", Version: 2}},
		{Type: DetachRoute, Route: &RouteRef{RouteID: "route", Version: 2}},
		{Type: RouteDrained, Route: &RouteRef{RouteID: "route", Version: 2}},
		{Type: WorkerDraining},
		{Type: Error, Route: &RouteRef{RouteID: "route", Version: 2}, Code: StaleAssignment},
	}
	for _, message := range controls {
		var wire bytes.Buffer
		if err := WriteControl(&wire, message); err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(0), wire.Bytes(), uint8(1))
	}
	var dataWire bytes.Buffer
	if err := WriteDataHeader(&dataWire, DataHeader{RouteID: "route", Version: 2}); err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(1), dataWire.Bytes(), uint8(1))
	f.Add(uint8(0), []byte{}, uint8(1))
	f.Add(uint8(0), []byte{0, 0, 0, 0}, uint8(2))
	f.Add(uint8(0), []byte{0, 1, 0, 1}, uint8(4))
	f.Add(uint8(1), []byte{0, 0, 4, 1}, uint8(4))
	f.Add(uint8(1), []byte{0, 0, 0, 1, '{'}, uint8(3))

	f.Fuzz(func(t *testing.T, kind uint8, input []byte, readSize uint8) {
		decodeCanonical := func(reader io.Reader) ([]byte, error) {
			var canonical bytes.Buffer
			if kind%2 == 0 {
				message, err := ReadControl(reader)
				if err != nil {
					return nil, err
				}
				if err := WriteControl(&canonical, message); err != nil {
					t.Fatal(err)
				}
			} else {
				header, err := ReadDataHeader(reader)
				if err != nil {
					return nil, err
				}
				if err := WriteDataHeader(&canonical, header); err != nil {
					t.Fatal(err)
				}
			}
			return canonical.Bytes(), nil
		}

		reader := &limitedReadReader{
			Reader: bytes.NewReader(input),
			Size:   int(readSize%32) + 1,
		}
		canonical, err := decodeCanonical(reader)
		if err != nil {
			return
		}
		if len(input) < 4 {
			t.Fatal("frame succeeded without a length header")
		}
		payloadBytes := int(binary.BigEndian.Uint32(input[:4]))
		if payloadBytes > len(input)-4 {
			t.Fatal("truncated frame succeeded")
		}
		remaining, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(remaining, input[4+payloadBytes:]) {
			t.Fatal("frame reader consumed trailing bytes")
		}

		roundTrip, err := decodeCanonical(bytes.NewReader(canonical))
		if err != nil {
			t.Fatalf("canonical frame was rejected: %v", err)
		}
		if !bytes.Equal(roundTrip, canonical) {
			t.Fatal("frame changed after canonical round trip")
		}
	})
}

type limitedReadReader struct {
	Reader io.Reader
	Size   int
}

func (r *limitedReadReader) Read(destination []byte) (int, error) {
	if len(destination) > r.Size {
		destination = destination[:r.Size]
	}
	return r.Reader.Read(destination)
}
