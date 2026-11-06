package daemon

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const postgresKernelSnapshotLimit = 16
const postgresKernelThreadLimit = 64
const postgresKernelTCPLimit = 128
const postgresKernelTCPBytes = 128 << 10
const postgresKernelLateness = 10 * time.Millisecond

const postgresKernelNotes = "best-effort, non-atomic proc metadata after sampler lateness >10ms; at most 16 snapshots, 64 threads per process and 128 loopback TCP rows; bounds use the visitor phase epoch and capture work is included in sample Completed; procfs reads are byte-bounded, not wall-time bounded: kernel waits may delay the sampler and Finish, with no hard deadline; TID is an OS thread ID, not a GoID; state R means running or runnable, wchan 0 is inconclusive; syscall arguments are never retained; TCP rows describe the network namespace, not socket ownership; unavailable or truncated reads do not establish absence of queued bytes; no schedstat or socket reads"

type postgresKernelBounds struct{ Started, Completed time.Duration }

type postgresKernelSnapshot struct {
	postgresKernelBounds
	TriggerLateness    time.Duration
	Visitor, Connector postgresKernelProcess
	TCP                postgresKernelTCP
}

type postgresKernelProcess struct {
	postgresKernelBounds
	PID                             int
	StartTimeTicks                  *uint64
	Identity                        string
	TimeNamespace, NetworkNamespace string
	Threads                         []postgresKernelThread
	ThreadsTruncated                bool
	Issues                          []string
}

type postgresKernelThread struct {
	postgresKernelBounds
	TID            int
	Stat           *postgresKernelThreadStat
	Wchan, Syscall string
	Issues         []string
}

type postgresKernelThreadStat struct {
	State          string
	Processor      int
	StartTimeTicks uint64
}

type postgresKernelTCP struct {
	postgresKernelBounds
	Entries   []postgresKernelTCPEntry
	Truncated bool
	Issue     string
}

type postgresKernelTCPEntry struct {
	LocalPort, RemotePort uint16
	TxQueue, RxQueue      uint64
	Inode                 uint64
}

// only the existing sampler calls this; no request worker, timer or new owner.
func (d *postgresLateDiagnostic) snapshotKernel(root string, sample postgresLateSample) {
	if sample.Lateness <= postgresKernelLateness {
		return
	}
	if len(d.kernels) >= postgresKernelSnapshotLimit {
		d.receipt.KernelSnapshotSkipped++
		return
	}
	s := postgresKernelSnapshot{TriggerLateness: sample.Lateness}
	s.Started = time.Since(d.cfg.Start)
	// read queues first: the connector may resume while thread metadata is read.
	s.TCP.Started = time.Since(d.cfg.Start)
	s.TCP.Issue = "tcp-unavailable"
	if d.cfg.ConnectorPID > 0 {
		data, issue := readPostgresKernelFile(filepath.Join(root, strconv.Itoa(d.cfg.ConnectorPID), "net/tcp"), postgresKernelTCPBytes)
		if issue == "" {
			s.TCP.Entries, s.TCP.Truncated, s.TCP.Issue = parsePostgresKernelTCP(data)
		} else {
			s.TCP.Truncated, s.TCP.Issue = issue == "truncated", "tcp-"+issue
		}
	}
	s.TCP.Completed = time.Since(d.cfg.Start)
	s.Connector = readPostgresKernelProcess(root, d.cfg.ConnectorPID, sample.Connector.StartTimeTicks, d.cfg.Start)
	s.Visitor = readPostgresKernelProcess(root, os.Getpid(), sample.Visitor.StartTimeTicks, d.cfg.Start)
	if s.Connector.Identity != "verified" {
		s.TCP.Entries, s.TCP.Issue = nil, "process-identity-unverified"
	}
	s.Completed = time.Since(d.cfg.Start)
	d.kernels = append(d.kernels, s)
}

func readPostgresKernelProcess(root string, pid int, expected uint64, epoch time.Time) (p postgresKernelProcess) {
	p.PID, p.Identity, p.Started = pid, "unavailable", time.Since(epoch)
	defer func() { p.Completed = time.Since(epoch) }()
	base := filepath.Join(root, strconv.Itoa(pid))
	readIdentity := func() (postgresLateProcess, bool) {
		data, issue := readPostgresKernelFile(filepath.Join(base, "stat"), 4096)
		stat, err := parsePostgresLateProcess(data)
		return stat, issue == "" && err == nil && stat.PID == pid && stat.StartTimeTicks > 0
	}
	stat, ok := readIdentity()
	if pid <= 0 || !ok {
		p.Issues = append(p.Issues, "process-stat-unavailable")
		return
	}
	p.StartTimeTicks = &stat.StartTimeTicks
	if expected == 0 {
		p.Identity, p.Issues = "unverified", append(p.Issues, "process-expected-identity-unavailable")
		return
	}
	if expected != stat.StartTimeTicks {
		p.Identity, p.Issues = "changed", append(p.Issues, "process-identity-changed")
		return
	}
	for _, ns := range []struct {
		name   string
		target *string
	}{{"time", &p.TimeNamespace}, {"net", &p.NetworkNamespace}} {
		link, err := os.Readlink(filepath.Join(base, "ns", ns.name))
		*ns.target = parsePostgresKernelNamespace(link, ns.name)
		if err != nil || *ns.target == "" {
			p.Issues = append(p.Issues, ns.name+"-namespace-unavailable")
		}
	}
	directory, err := os.Open(filepath.Join(base, "task"))
	if err != nil {
		p.Issues = append(p.Issues, "task-list-unavailable")
	} else {
		entries, err := directory.ReadDir(postgresKernelThreadLimit + 1)
		_ = directory.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			p.Issues = append(p.Issues, "task-list-unavailable")
		}
		tids := make([]int, 0, len(entries))
		for _, entry := range entries {
			if tid, err := strconv.Atoi(entry.Name()); err == nil && tid > 0 {
				tids = append(tids, tid)
			} else {
				p.Issues = append(p.Issues, "task-id-invalid")
			}
		}
		slices.Sort(tids)
		p.ThreadsTruncated = len(entries) > postgresKernelThreadLimit
		for _, tid := range tids[:min(len(tids), postgresKernelThreadLimit)] {
			p.Threads = append(p.Threads, readPostgresKernelThread(filepath.Join(base, "task", strconv.Itoa(tid)), tid, epoch, readPostgresKernelFile))
		}
	}
	if after, ok := readIdentity(); !ok {
		p.Issues = append(p.Issues, "process-stat-unavailable-after-read")
		return
	} else if after.StartTimeTicks != stat.StartTimeTicks {
		p.Identity, p.Issues = "changed", append(p.Issues, "process-identity-changed")
		return
	}
	p.Identity = "verified"
	return
}

func readPostgresKernelThread(base string, tid int, epoch time.Time, read func(string, int64) (string, string)) (t postgresKernelThread) {
	t.TID, t.Started = tid, time.Since(epoch)
	defer func() { t.Completed = time.Since(epoch) }()
	data, issue := read(filepath.Join(base, "stat"), 4096)
	if stat, ok := parsePostgresKernelThread(data, tid); issue == "" && ok {
		t.Stat = &stat
	} else {
		t.Issues = append(t.Issues, "thread-stat-unavailable")
		return
	}
	for _, field := range []struct {
		name   string
		parse  func(string) string
		target *string
	}{{"wchan", parsePostgresKernelWchan, &t.Wchan}, {"syscall", parsePostgresKernelSyscall, &t.Syscall}} {
		data, issue := read(filepath.Join(base, field.name), 4096)
		if issue == "" {
			*field.target = field.parse(data)
		}
		if *field.target == "" {
			t.Issues = append(t.Issues, field.name+"-unavailable")
		}
	}
	data, issue = read(filepath.Join(base, "stat"), 4096)
	if after, ok := parsePostgresKernelThread(data, tid); issue != "" || !ok {
		t.Issues = append(t.Issues, "thread-stat-unavailable-after-read")
	} else if after.StartTimeTicks != t.Stat.StartTimeTicks {
		t.Issues = append(t.Issues, "thread-identity-changed")
	} else {
		return
	}
	// never combine metadata from different or unverified thread incarnations.
	t.Stat, t.Wchan, t.Syscall = nil, "", ""
	return
}

// read at most limit+1 bytes and never retain partial files or OS error text.
// procfs kernel waits have no hard deadline and can delay the sampler and Finish.
func readPostgresKernelFile(path string, limit int64) (string, string) {
	f, err := os.Open(path)
	if err != nil {
		return "", "unavailable"
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return "", "unavailable"
	}
	if int64(len(data)) > limit {
		return "", "truncated"
	}
	return string(data), ""
}

func parsePostgresKernelThread(text string, tid int) (postgresKernelThreadStat, bool) {
	p, err := parsePostgresLateProcess(text)
	fields := strings.Fields(text[strings.LastIndexByte(text, ')')+1:])
	if err != nil || p.PID != tid || p.StartTimeTicks == 0 || len(fields) < 37 || len(fields[0]) != 1 || !strings.Contains("RSDZTWtXxKWPI", fields[0]) {
		return postgresKernelThreadStat{}, false
	}
	cpu, err := strconv.Atoi(fields[36])
	return postgresKernelThreadStat{State: string(fields[0][0]), Processor: cpu, StartTimeTicks: p.StartTimeTicks}, err == nil && cpu >= 0
}

func parsePostgresKernelSyscall(text string) string {
	token := strings.TrimSpace(text)
	if end := strings.IndexAny(token, " \t\r\n"); end >= 0 {
		token = token[:end]
	}
	switch token {
	case "running":
		return "running"
	case "unsupported":
		return "unsupported"
	}
	if number, err := strconv.ParseInt(token, 10, 64); err == nil && number >= -1 {
		return strconv.FormatInt(number, 10)
	}
	return ""
}

func parsePostgresKernelWchan(text string) string {
	text = strings.TrimSpace(text)
	if len(text) == 0 || len(text) > 64 {
		return ""
	}
	for _, c := range text {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return ""
		}
	}
	return strings.Clone(text)
}

func parsePostgresKernelNamespace(text, name string) string {
	if len(text) > 64 || !strings.HasPrefix(text, name+":[") || !strings.HasSuffix(text, "]") {
		return ""
	}
	id := text[len(name)+2 : len(text)-1]
	if number, err := strconv.ParseUint(id, 10, 64); err == nil && number > 0 {
		return strconv.FormatUint(number, 10)
	}
	return ""
}

func parsePostgresKernelTCP(text string) ([]postgresKernelTCPEntry, bool, string) {
	header, rows, ok := strings.Cut(text, "\n")
	if !ok || !strings.Contains(header, "local_address") || !strings.Contains(header, "inode") || !strings.HasSuffix(text, "\n") {
		return nil, false, "tcp-invalid-or-truncated"
	}
	entries := make([]postgresKernelTCPEntry, 0, postgresKernelTCPLimit)
	truncated := false
	for line := range strings.SplitSeq(strings.TrimSpace(rows), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return nil, false, "tcp-invalid-or-truncated"
		}
		local, lp, _ := strings.Cut(fields[1], ":")
		remote, rp, _ := strings.Cut(fields[2], ":")
		if fields[3] != "01" || local != "0100007F" || remote != "0100007F" {
			continue
		}
		tx, rx, ok := strings.Cut(fields[4], ":")
		values := [5]uint64{}
		for i, raw := range []string{lp, rp, tx, rx, fields[9]} {
			base, bits := 16, 64
			if i < 2 {
				bits = 16
			}
			if i == 4 {
				base = 10
			}
			value, err := strconv.ParseUint(raw, base, bits)
			if err != nil || !ok || (i < 2 && value == 0) {
				return nil, false, "tcp-invalid-or-truncated"
			}
			values[i] = value
		}
		if len(entries) == postgresKernelTCPLimit {
			truncated = true
			continue
		}
		entries = append(entries, postgresKernelTCPEntry{LocalPort: uint16(values[0]), RemotePort: uint16(values[1]), TxQueue: values[2], RxQueue: values[3], Inode: values[4]})
	}
	return entries, truncated, ""
}
