package target

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

var dockerOutputBytes = flag.Int("tnl-docker-output-bytes", 0, "fixture Docker output size")

func TestDockerOutputProcess(t *testing.T) {
	if *dockerOutputBytes == 0 {
		return
	}
	_, _ = os.Stdout.Write(bytes.Repeat([]byte{'d'}, *dockerOutputBytes))
	os.Exit(0)
}

func TestDockerOutputBoundThroughCopyAndSubprocess(t *testing.T) {
	const limit = 8 << 20
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir()
	if err := os.Symlink(binary, filepath.Join(path, "docker")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", path)
	for _, size := range []int{limit, limit + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			data := bytes.Repeat([]byte{'d'}, size)
			var output boundedBuffer
			// hide WriterTo so io.Copy must choose the destination's methods.
			_, err := io.Copy(&output, struct{ io.Reader }{bytes.NewReader(data)})
			if (err == nil) != (size == limit) || output.buffer.Len() > limit {
				t.Fatalf("copy captured %d bytes, error %v", output.buffer.Len(), err)
			}
			if size == limit && !bytes.Equal(output.buffer.Bytes(), data) {
				t.Fatal("copy changed exact-bound output")
			}
			got, err := (CLI{}).Run(t.Context(), nil, "-test.run=^TestDockerOutputProcess$", "-tnl-docker-output-bytes="+strconv.Itoa(size))
			if (err == nil) != (size == limit) || size == limit && !bytes.Equal(got, data) || size > limit && got != nil {
				t.Fatalf("subprocess captured %d bytes, error %v", len(got), err)
			}
		})
	}
}
