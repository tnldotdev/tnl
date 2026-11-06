package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func postgresKernelStatFixture(tid int, ticks uint64) string {
	fields := make([]string, 37)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[17], fields[19], fields[36] = "S", "1", strconv.FormatUint(ticks, 10), "7"
	return fmt.Sprintf("%d (worker ) private ( name) %s\n", tid, strings.Join(fields, " "))
}

const postgresKernelTCPHeader = "  sl local_address rem_address st tx_queue:rx_queue tr tm->when retrnsmt uid timeout inode\n"
const postgresKernelTCPRow = "  0: 0100007F:9610 0100007F:CAFE 01 0000000A:00000023 00:00000000 00000000 1000 0 12345\n"

func TestPostgresKernelParsers(t *testing.T) {
	fixture := postgresKernelStatFixture(17, 999)
	stat, ok := parsePostgresKernelThread(fixture, 17)
	if !ok || stat != (postgresKernelThreadStat{State: "S", Processor: 7, StartTimeTicks: 999}) {
		t.Fatalf("stat=%+v valid=%t", stat, ok)
	}
	for _, bad := range []string{"", "17 (worker) S", strings.Replace(fixture, "999", "bad", 1), strings.Replace(fixture, ") S", ") ?", 1), strings.TrimSuffix(fixture, "7\n"), strings.TrimSuffix(fixture, "7\n") + "-1"} {
		if _, ok := parsePostgresKernelThread(bad, 17); ok {
			t.Fatalf("accepted invalid stat %q", bad)
		}
	}
	if _, ok := parsePostgresKernelThread(fixture, 18); ok {
		t.Fatal("accepted another thread's stat")
	}
	for input, want := range map[string]string{"22 0xsecret 0xpointer 999\n": "22", "-1 0xsecret": "-1", " running\n": "running", "unsupported": "unsupported", "63\tprivate": "63", "": "", "private": "", "-2 0xpointer": ""} {
		if got := parsePostgresKernelSyscall(input); got != want {
			t.Fatalf("syscall=%q want=%q", got, want)
		}
	}
	for input, want := range map[string]string{"ep_poll\n": "ep_poll", "0": "0", strings.Repeat("x", 64): strings.Repeat("x", 64), strings.Repeat("x", 65): "", "wait private": "", "wait\x00": "", "wáit": ""} {
		if got := parsePostgresKernelWchan(input); got != want {
			t.Fatalf("wchan=%q want=%q", got, want)
		}
	}
	for input, want := range map[string]string{"net:[4026531992]": "4026531992", "net:[]": "", "net:[bad]": "", "net:[0]": "", "time:[42]": "", strings.Repeat("x", 65): ""} {
		if got := parsePostgresKernelNamespace(input, "net"); got != want {
			t.Fatalf("namespace=%q want=%q", got, want)
		}
	}
}

func TestPostgresKernelTCPParser(t *testing.T) {
	filtered := strings.ReplaceAll(postgresKernelTCPRow, "0100007F", "0000007F") + strings.Replace(postgresKernelTCPRow, "01 0000000A", "0A 0000000A", 1) + strings.Replace(postgresKernelTCPRow, "0100007F:CAFE", "0200007F:CAFE", 1)
	rows, truncated, issue := parsePostgresKernelTCP(postgresKernelTCPHeader + postgresKernelTCPRow + filtered)
	want := postgresKernelTCPEntry{LocalPort: 38416, RemotePort: 51966, TxQueue: 10, RxQueue: 35, Inode: 12345}
	if issue != "" || truncated || len(rows) != 1 || rows[0] != want {
		t.Fatalf("rows=%+v truncated=%t issue=%s", rows, truncated, issue)
	}
	rows, truncated, issue = parsePostgresKernelTCP(postgresKernelTCPHeader + strings.Repeat(postgresKernelTCPRow, postgresKernelTCPLimit+1))
	if issue != "" || !truncated || len(rows) != postgresKernelTCPLimit {
		t.Fatalf("row cap=%d truncated=%t issue=%s", len(rows), truncated, issue)
	}
	for _, bad := range []string{"", postgresKernelTCPHeader + "short\n", strings.TrimSuffix(postgresKernelTCPHeader+postgresKernelTCPRow, "\n"), postgresKernelTCPHeader + strings.Replace(postgresKernelTCPRow, ":9610", ":10000", 1), postgresKernelTCPHeader + strings.Replace(postgresKernelTCPRow, "00000023", "bad!", 1), postgresKernelTCPHeader + strings.Replace(postgresKernelTCPRow, "12345", "private", 1)} {
		if rows, _, issue := parsePostgresKernelTCP(bad); issue == "" || rows != nil {
			t.Fatalf("invalid table claimed usable queues: %+v %q", rows, issue)
		}
	}
}

func writePostgresKernelFixture(t *testing.T, root, path, data string) {
	t.Helper()
	path = filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func preparePostgresKernelProcessFixture(t *testing.T, root string, pid, threads int) {
	t.Helper()
	base := strconv.Itoa(pid)
	writePostgresKernelFixture(t, root, base+"/stat", postgresKernelStatFixture(pid, 999))
	for _, ns := range []string{"net", "time"} {
		path := filepath.Join(root, base, "ns", ns)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(ns+":[42]", path); err != nil {
			t.Fatal(err)
		}
	}
	for tid := 1; tid <= threads; tid++ {
		path := fmt.Sprintf("%s/task/%d/", base, tid)
		writePostgresKernelFixture(t, root, path+"stat", postgresKernelStatFixture(tid, 1000+uint64(tid)))
		writePostgresKernelFixture(t, root, path+"wchan", "ep_poll\n")
		writePostgresKernelFixture(t, root, path+"syscall", "22 0xprivate-pointer private-arguments\n")
	}
}

func TestPostgresKernelSnapshotBoundsAndFailures(t *testing.T) {
	root := t.TempDir()
	const pid = 123
	preparePostgresKernelProcessFixture(t, root, pid, postgresKernelThreadLimit+2)
	preparePostgresKernelProcessFixture(t, root, os.Getpid(), 1)
	writePostgresKernelFixture(t, root, "123/net/tcp", postgresKernelTCPHeader+postgresKernelTCPRow)
	// listed threads can disappear before their metadata reads; keep the issue.
	if err := os.Remove(filepath.Join(root, "123/task/1/stat")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "123/task/2/syscall")); err != nil {
		t.Fatal(err)
	}
	epoch := time.Now().Add(-time.Second)
	d := &postgresLateDiagnostic{cfg: postgresLateConfig{Start: epoch, ConnectorPID: pid}, kernels: make([]postgresKernelSnapshot, 0, postgresKernelSnapshotLimit)}
	sample := postgresLateSample{Lateness: postgresKernelLateness, Visitor: postgresLateProcess{StartTimeTicks: 999}, Connector: postgresLateProcess{StartTimeTicks: 999}}
	d.snapshotKernel(root, sample)
	if len(d.kernels) != 0 {
		t.Fatal("exact-threshold sample captured kernel state")
	}
	sample.Lateness++
	for range postgresKernelSnapshotLimit + 3 {
		d.snapshotKernel(root, sample)
	}
	if len(d.kernels) != postgresKernelSnapshotLimit || cap(d.kernels) != postgresKernelSnapshotLimit || d.receipt.KernelSnapshotSkipped != 3 || d.err != nil {
		t.Fatalf("snapshot cap or best-effort policy: count=%d capacity=%d receipt=%+v error=%v", len(d.kernels), cap(d.kernels), d.receipt, d.err)
	}
	s := d.kernels[0]
	p := s.Connector
	if s.TriggerLateness != sample.Lateness || p.Identity != "verified" || p.StartTimeTicks == nil || *p.StartTimeTicks != 999 || p.TimeNamespace != "42" || p.NetworkNamespace != "42" || !p.ThreadsTruncated || len(p.Threads) != postgresKernelThreadLimit || len(s.TCP.Entries) != 1 || s.TCP.Issue != "" {
		t.Fatalf("snapshot lost bounded metadata: %+v", s)
	}
	last := 0
	for _, thread := range p.Threads {
		if thread.TID <= last || thread.Completed < thread.Started || thread.Started < p.Started || thread.Completed > p.Completed {
			t.Fatalf("thread ordering or read bounds: %+v", thread)
		}
		last = thread.TID
		if thread.TID == 1 && (thread.Stat != nil || !slices.Contains(thread.Issues, "thread-stat-unavailable")) || thread.TID == 2 && (thread.Syscall != "" || !slices.Contains(thread.Issues, "syscall-unavailable")) {
			t.Fatalf("disappearing metadata silently became a zero: %+v", thread)
		}
	}
	if s.Started < time.Second || s.TCP.Started < s.Started || s.TCP.Completed < s.TCP.Started || p.Started < s.TCP.Completed || s.Visitor.Started < p.Completed || s.Completed < s.Visitor.Completed {
		t.Fatalf("snapshot read bounds: %+v", s)
	}
	encoded, err := json.Marshal(s)
	if err != nil || strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), "pointer") || strings.Contains(string(encoded), root) {
		t.Fatalf("snapshot leaked proc text or error details: %s error=%v", encoded, err)
	}
	p = readPostgresKernelProcess(root, pid, 998, epoch)
	if p.Identity != "changed" || len(p.Threads) != 0 || !slices.Contains(p.Issues, "process-identity-changed") {
		t.Fatalf("PID reuse was accepted: %+v", p)
	}
	p = readPostgresKernelProcess(root, 456, 0, epoch)
	if p.Identity != "unavailable" || p.StartTimeTicks != nil || len(p.Issues) == 0 {
		t.Fatalf("missing process claimed identity: %+v", p)
	}
	writePostgresKernelFixture(t, root, "oversized", strings.Repeat("x", postgresKernelTCPBytes+1))
	if data, issue := readPostgresKernelFile(filepath.Join(root, "oversized"), postgresKernelTCPBytes); data != "" || issue != "truncated" {
		t.Fatal("oversized file retained partial content")
	}
	d.kernels = d.kernels[:0]
	writePostgresKernelFixture(t, root, "123/net/tcp", "invalid\n")
	d.snapshotKernel(root, sample)
	if s := d.kernels[0]; s.TCP.Entries != nil || s.TCP.Issue == "" || d.err != nil {
		t.Fatalf("invalid TCP metadata was usable or fatal: %+v error=%v", s, d.err)
	}
	d.kernels = d.kernels[:0]
	writePostgresKernelFixture(t, root, "123/net/tcp", strings.Repeat("x", postgresKernelTCPBytes+1))
	d.snapshotKernel(root, sample)
	if s := d.kernels[0]; s.TCP.Entries != nil || s.TCP.Issue != "tcp-truncated" || !s.TCP.Truncated {
		t.Fatalf("oversized TCP table lost its truncation: %+v", s.TCP)
	}
	d.kernels = d.kernels[:0]
	if err := os.Remove(filepath.Join(root, "123/net/tcp")); err != nil {
		t.Fatal(err)
	}
	d.snapshotKernel(root, sample)
	if s := d.kernels[0]; s.TCP.Entries != nil || s.TCP.Issue != "tcp-unavailable" || d.err != nil {
		t.Fatalf("unavailable TCP table claimed queues or failed the benchmark: %+v", s.TCP)
	}
}

func TestPostgresKernelUnknownProcessIdentity(t *testing.T) {
	root := t.TempDir()
	preparePostgresKernelProcessFixture(t, root, 123, 1)
	writePostgresKernelFixture(t, root, "123/net/tcp", postgresKernelTCPHeader+postgresKernelTCPRow)
	epoch := time.Now()
	p := readPostgresKernelProcess(root, 123, 0, epoch)
	if p.Identity != "unverified" || p.StartTimeTicks == nil || *p.StartTimeTicks != 999 || len(p.Threads) != 0 || !slices.Contains(p.Issues, "process-expected-identity-unavailable") {
		t.Fatalf("unknown expected identity accepted replacement process: %+v", p)
	}
	// the sampler leaves Connector zero-valued when its saved identity mismatches.
	data, issue := readPostgresKernelFile(filepath.Join(root, "123/stat"), 4096)
	observed, err := parsePostgresLateProcess(data)
	if issue != "" || err != nil {
		t.Fatal("invalid replacement fixture")
	}
	sample := postgresLateSample{Lateness: postgresKernelLateness + 1}
	const savedIdentity = 998
	if observed.StartTimeTicks == savedIdentity {
		sample.Connector = observed
	}
	d := &postgresLateDiagnostic{cfg: postgresLateConfig{Start: epoch, ConnectorPID: 123}, kernels: make([]postgresKernelSnapshot, 0, postgresKernelSnapshotLimit)}
	d.snapshotKernel(root, sample)
	s := d.kernels[0]
	if s.Connector.Identity != "unverified" || s.TCP.Entries != nil || s.TCP.Issue != "process-identity-unverified" || d.err != nil {
		t.Fatalf("zeroed sampler identity retained replacement TCP rows or was fatal: %+v error=%v", s, d.err)
	}
}

func TestPostgresKernelThreadIdentityRecheck(t *testing.T) {
	for _, mode := range []string{"stable", "replaced", "unavailable", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			var reads []string
			statReads := 0
			read := func(path string, limit int64) (string, string) {
				name := filepath.Base(path)
				reads = append(reads, name)
				if limit != 4096 {
					t.Fatal("metadata read lost its byte bound")
				}
				switch name {
				case "stat":
					statReads++
					if statReads == 2 {
						switch mode {
						case "replaced":
							return postgresKernelStatFixture(17, 1001), ""
						case "unavailable":
							return "", "unavailable"
						case "invalid":
							return "invalid", ""
						}
					}
					return postgresKernelStatFixture(17, 1000), ""
				case "wchan":
					return "ep_poll\n", ""
				case "syscall":
					return "22 private arguments", ""
				default:
					t.Fatal("unexpected metadata read")
					return "", "unavailable"
				}
			}
			thread := readPostgresKernelThread("fixture", 17, time.Now(), read)
			if !slices.Equal(reads, []string{"stat", "wchan", "syscall", "stat"}) {
				t.Fatalf("identity did not bracket metadata: %v", reads)
			}
			if mode == "stable" {
				if thread.Stat == nil || thread.Stat.StartTimeTicks != 1000 || thread.Wchan != "ep_poll" || thread.Syscall != "22" || len(thread.Issues) != 0 {
					t.Fatalf("stable metadata lost: %+v", thread)
				}
			} else if thread.Stat != nil || thread.Wchan != "" || thread.Syscall != "" || len(thread.Issues) == 0 {
				t.Fatalf("unverified thread metadata remained usable: %+v", thread)
			}
		})
	}
}

func TestPostgresKernelLiveProcLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("live procfs qualification requires Linux")
	}
	pid := os.Getpid()
	data, issue := readPostgresKernelFile(fmt.Sprintf("/proc/%d/stat", pid), 4096)
	known, err := parsePostgresLateProcess(data)
	if issue != "" || err != nil || known.PID != pid || known.StartTimeTicks == 0 {
		t.Fatal("own process identity unavailable")
	}
	p := readPostgresKernelProcess("/proc", pid, known.StartTimeTicks, time.Now())
	if p.Identity != "verified" || p.StartTimeTicks == nil || *p.StartTimeTicks != known.StartTimeTicks || len(p.Threads) == 0 {
		t.Fatalf("live process/task metadata invalid: %+v", p)
	}
	for _, ns := range []struct{ value, issue string }{{p.TimeNamespace, "time-namespace-unavailable"}, {p.NetworkNamespace, "net-namespace-unavailable"}} {
		if ns.value == "" && !slices.Contains(p.Issues, ns.issue) {
			t.Fatal("optional live namespace silently unavailable")
		}
	}
	usable := 0
	for _, thread := range p.Threads {
		if thread.Stat == nil {
			if len(thread.Issues) == 0 {
				t.Fatal("disappearing live thread silently unavailable")
			}
			continue
		}
		usable++
		if thread.TID <= 0 || thread.Stat.StartTimeTicks == 0 || thread.Completed < thread.Started || (thread.Wchan == "" && !slices.Contains(thread.Issues, "wchan-unavailable")) || (thread.Syscall == "" && !slices.Contains(thread.Issues, "syscall-unavailable")) {
			t.Fatalf("optional live fields silently unavailable: %+v", thread)
		}
	}
	if usable == 0 {
		t.Fatal("no live thread retained a verified identity")
	}
}

func TestPostgresKernelSnapshotExportAfterJoin(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancelled=%t", cancelled), func(t *testing.T) {
			testPostgresKernelSnapshotExport(t, cancelled)
		})
	}
}

func testPostgresKernelSnapshotExport(t *testing.T, cancelled bool) {
	root := t.TempDir()
	directory := filepath.Join(root, "artifacts")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	d := startPostgresLateDiagnostic(ctx, postgresLateConfig{Mode: "sample", Start: time.Now().Add(time.Hour), Duration: time.Minute})
	defer func() { _ = d.Finish(directory) }()
	if len(d.kernels) != 0 || cap(d.kernels) != postgresKernelSnapshotLimit {
		t.Fatal("snapshot storage was not preallocated")
	}
	d.snapshotKernel(root, postgresLateSample{Lateness: postgresKernelLateness + 1})
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("snapshot wrote in phase")
	}
	var wantErr error
	if cancelled {
		cancel()
		wantErr = context.Canceled
	}
	if err := d.Finish(directory); !errors.Is(err, wantErr) {
		t.Fatalf("export error=%v want=%v", err, wantErr)
	}
	r := readPostgresLateReceipt(t, directory)
	if r.KernelSnapshotCount != 1 || r.KernelSnapshotLimit != postgresKernelSnapshotLimit || r.KernelSnapshotFile != "kernel-snapshots.json" || r.KernelSnapshotNotes == "" || d.kernels != nil {
		t.Fatalf("snapshot receipt or release: %+v", r)
	}
	path := filepath.Join(directory, r.KernelSnapshotFile)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot not private: %v %v", info, err)
	}
	data, err := os.ReadFile(path)
	var snapshots []postgresKernelSnapshot
	if err != nil || json.Unmarshal(data, &snapshots) != nil || len(snapshots) != 1 || snapshots[0].TCP.Issue == "" || snapshots[0].Connector.Identity != "unavailable" {
		t.Fatalf("best-effort failures lost on export: %s error=%v", data, err)
	}
}
