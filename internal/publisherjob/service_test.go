package publisherjob

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestServiceUnitsAreBootStartedAndContainNoEnrollmentArguments(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			binary, root := "/private/tnl & test/bin/tnl", "/private/tnl & test/state"
			unit, err := ServiceUnit(platform, binary, root)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"--enroll-key", "--publisher-id", "--credential", "--target", "Environment=", "StandardOutPath", "StandardErrorPath"} {
				if strings.Contains(string(unit), forbidden) {
					t.Fatalf("secret/publication argument in unit: %s", forbidden)
				}
			}
			if platform == "darwin" {
				decoder := xml.NewDecoder(strings.NewReader(string(unit)))
				var values []string
				for {
					token, err := decoder.Token()
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					if start, ok := token.(xml.StartElement); ok && start.Name.Local == "string" {
						var value string
						if err := decoder.DecodeElement(&value, &start); err != nil {
							t.Fatal(err)
						}
						values = append(values, value)
					}
				}
				if !reflect.DeepEqual(values, []string{ServiceLabel, binary, "service", "serve", "--system-state-dir", root, "root"}) {
					t.Fatalf("LaunchDaemon argv: %q", values)
				}
				for _, expected := range []string{"<key>RunAtLoad</key><true/>", "<key>KeepAlive</key><true/>", "<key>ExitTimeOut</key><integer>45</integer>"} {
					if !strings.Contains(string(unit), expected) {
						t.Fatalf("missing boot/drain setting: %s", expected)
					}
				}
			} else {
				for _, expected := range []string{"User=root", "WantedBy=multi-user.target", "Restart=always", "TimeoutStopSec=45", `ExecStart="/private/tnl & test/bin/tnl" service serve --system-state-dir "/private/tnl & test/state"`} {
					if !strings.Contains(string(unit), expected) {
						t.Fatalf("missing systemd setting: %s", expected)
					}
				}
			}
		})
	}
	for _, root := range []string{"relative", "/tmp/unsafe\npath", "/tmp/%n", "/tmp/../etc"} {
		if _, err := ServiceUnit("linux", "/private/bin/tnl", root); err == nil {
			t.Fatalf("unsafe systemd path accepted: %q", root)
		}
	}
	unit, err := ServiceUnit("linux", "/private/$BINARY", "/private/$STATE")
	if err != nil || !strings.Contains(string(unit), "$$BINARY") || !strings.Contains(string(unit), "$$STATE") {
		t.Fatalf("systemd expanded a path as an environment variable: %s, %v", unit, err)
	}
}

func TestServiceRefreshDoesNotHoldTheRegistryDuringRestart(t *testing.T) {
	options := testOptions(t)
	source := filepath.Join(filepath.Dir(options.Root), "source")
	if err := os.WriteFile(source, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	service := ServiceOptions{Platform: "linux", Root: options.Root, BinarySource: source, TestOwnerUID: options.TestOwnerUID, TestUnitDir: filepath.Join(filepath.Dir(options.Root), "units")}
	executor := ExecutorFunc(func(ctx context.Context, command Command) error {
		if command.Args[0] != "restart" {
			return nil
		}
		finish, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		registry, err := Open(finish, options)
		if err != nil {
			return err
		}
		defer registry.Close()
		_, err = registry.List(finish)
		return err
	})
	if err := InstallService(t.Context(), service, executor); err != nil {
		t.Fatalf("restart blocked the draining publisher: %v", err)
	}
}

func TestServiceInstallRefreshAndCommandSemantics(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			options := testOptions(t)
			parent := filepath.Dir(options.Root)
			source := filepath.Join(parent, "source")
			if err := os.WriteFile(source, []byte("new binary one"), 0o700); err != nil {
				t.Fatal(err)
			}
			service := ServiceOptions{Platform: platform, Root: options.Root, BinarySource: source, TestOwnerUID: options.TestOwnerUID, TestUnitDir: filepath.Join(parent, "units")}
			var commands []Command
			loaded := false
			executor := ExecutorFunc(func(_ context.Context, command Command) error {
				commands = append(commands, command)
				if platform == "darwin" && command.Args[0] == "print" && !loaded {
					return ErrServiceNotLoaded
				}
				return nil
			})
			for refresh := range 2 {
				if refresh == 1 {
					loaded = true
					commands = nil
					if err := os.WriteFile(source, []byte("new binary two"), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if err := InstallService(t.Context(), service, executor); err != nil {
					t.Fatal(err)
				}
				installed := filepath.Join(options.Root, "bin", "tnl")
				value, err := os.ReadFile(installed)
				if err != nil {
					t.Fatal(err)
				}
				want := "new binary one"
				if refresh == 1 {
					want = "new binary two"
				}
				if string(value) != want {
					t.Fatalf("binary was not refreshed: %s", value)
				}
				info, err := os.Lstat(installed)
				if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o700 {
					t.Fatal("installed binary is not private")
				}
				var expected []Command
				if platform == "darwin" {
					expected = []Command{{"/bin/launchctl", []string{"print", "system/" + ServiceLabel}}}
					if loaded {
						expected = append(expected, Command{"/bin/launchctl", []string{"bootout", "system/" + ServiceLabel}})
					}
					expected = append(expected, Command{"/bin/launchctl", []string{"bootstrap", "system", filepath.Join(service.TestUnitDir, ServiceLabel+".plist")}})
				} else {
					expected = []Command{{"/bin/systemctl", []string{"daemon-reload"}}, {"/bin/systemctl", []string{"enable", SystemdUnit}}, {"/bin/systemctl", []string{"restart", SystemdUnit}}}
				}
				if !reflect.DeepEqual(commands, expected) {
					t.Fatalf("manager commands: %#v, want %#v", commands, expected)
				}
			}
			commands = nil
			if err := StartService(t.Context(), service, executor); err != nil {
				t.Fatal(err)
			}
			expected := Command{"/bin/systemctl", []string{"start", SystemdUnit}}
			if platform == "darwin" {
				expected = Command{"/bin/launchctl", []string{"kickstart", "system/" + ServiceLabel}}
			}
			if len(commands) != 1 || !reflect.DeepEqual(commands[0], expected) {
				t.Fatalf("start unexpectedly restarted/disabled other jobs: %#v", commands)
			}
		})
	}
}

func TestServiceInstallRejectsUnsafeDestinationsAndManagerFailures(t *testing.T) {
	for _, unsafe := range []string{"binary symlink", "unit symlink", "binary mode", "manager failure"} {
		t.Run(unsafe, func(t *testing.T) {
			options := testOptions(t)
			parent := filepath.Dir(options.Root)
			source := filepath.Join(parent, "source")
			if err := os.WriteFile(source, []byte("binary"), 0o700); err != nil {
				t.Fatal(err)
			}
			service := ServiceOptions{Platform: "linux", Root: options.Root, BinarySource: source, TestOwnerUID: options.TestOwnerUID, TestUnitDir: filepath.Join(parent, "units")}
			fake := ExecutorFunc(func(context.Context, Command) error { return nil })
			if err := InstallService(t.Context(), service, fake); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(options.Root, "bin", "tnl")
			path := binary
			if unsafe == "unit symlink" {
				path = filepath.Join(service.TestUnitDir, SystemdUnit)
			}
			if strings.HasSuffix(unsafe, "symlink") {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(source, path); err != nil {
					t.Fatal(err)
				}
			}
			if unsafe == "binary mode" {
				if err := os.Chmod(binary, 0o777); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			expected := errors.New("manager could not start")
			fake = ExecutorFunc(func(context.Context, Command) error { calls++; return expected })
			err := InstallService(t.Context(), service, fake)
			if unsafe == "manager failure" {
				if !errors.Is(err, expected) || calls != 1 {
					t.Fatalf("manager failure was ignored: %v, %d", err, calls)
				}
			} else if !errors.Is(err, ErrUnsafeState) || calls != 0 {
				t.Fatalf("unsafe destination reached manager: %v, %d", err, calls)
			}
		})
	}
}
