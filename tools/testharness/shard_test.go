package main

import (
	"fmt"
	"os/exec"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestShardsCoverEveryTestOnceAndRemainStable(t *testing.T) {
	var names []string
	for i := range 300 {
		names = append(names, fmt.Sprintf("TestIntegrationCase%d", i))
	}
	for _, count := range []int{3, 4} {
		seen := make(map[string]int)
		for index := 1; index <= count; index++ {
			shard := testShard{index: index, count: count}
			pattern, _, total, err := shardTestPattern(strings.Join(names, "\n"), "^TestIntegration", "", shard)
			if err != nil || total != len(names) {
				t.Fatalf("shard %v: total=%d, err=%v", shard, total, err)
			}
			matches := regexp.MustCompile(pattern)
			for _, name := range names {
				if matches.MatchString(name) {
					seen[name]++
					if matches.MatchString(name + "UnselectedSuffix") {
						t.Fatalf("shard selected a test by prefix: %s", name)
					}
				}
			}
			reordered := slices.Clone(names)
			slices.Reverse(reordered)
			updated, _, _, err := shardTestPattern(strings.Join(append(reordered, "TestIntegrationNewCase"), "\n"), "^TestIntegration", "", shard)
			if err != nil {
				t.Fatal(err)
			}
			updatedMatches := regexp.MustCompile(updated)
			for _, name := range names {
				if matches.MatchString(name) != updatedMatches.MatchString(name) {
					t.Fatalf("adding or reordering tests moved %s between shards", name)
				}
			}
		}
		for _, name := range names {
			if seen[name] != 1 {
				t.Fatalf("test %s assigned %d times with %d shards", name, seen[name], count)
			}
		}
	}
}

func TestShardDiscoveryAndExecutionPreserveFlagsAndExclusions(t *testing.T) {
	seen := make(map[string]int)
	for _, shard := range []string{"1/2", "2/2"} {
		command := []string{"go", "test", "-v", "./testdata/shards", "-run", "^Test", "-skip=^TestIgnored$", "-count=1", "-args", "-tnl-probe=kept"}
		selected, err := shardGoTestCommand(t.Context(), ".", command, shard)
		if err != nil {
			t.Fatal(err)
		}
		output, err := exec.CommandContext(t.Context(), selected[0], selected[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("run shard %s: %v\n%s", shard, err, output)
		}
		for line := range strings.SplitSeq(string(output), "\n") {
			if name, ok := strings.CutPrefix(line, "=== RUN   "); ok {
				seen[name]++
			}
		}
	}
	for _, name := range []string{"TestAlpha", "TestAlphabet", "TestBeta", "TestGamma"} {
		if seen[name] != 1 {
			t.Fatalf("test %s executed %d times", name, seen[name])
		}
	}
	if len(seen) != 4 {
		t.Fatalf("unexpected test execution: %v", seen)
	}
}

func TestShardRejectsMissingTestsAndInvalidSelection(t *testing.T) {
	for _, value := range []string{"1", "0/4", "5/4", "1/0", "1/65", "one/4", "1/4/5"} {
		if _, err := parseTestShard(value); err == nil {
			t.Fatalf("accepted invalid shard %q", value)
		}
	}
	for _, command := range [][]string{
		{"go", "test", "."},
		{"go", "test", ".", "-run=Test/subtest"},
		{"go", "test", ".", "-run=Test", "-run=Other"},
		{"go", "test", ".", "-run=Test", "-list=Test"},
		{"go", "test", ".", "-run"},
		{"other", "test", ".", "-run=Test"},
	} {
		if _, err := shardGoTestCommand(t.Context(), ".", command, "1/4"); err == nil {
			t.Fatalf("accepted unsupported shard command %v", command)
		}
	}
	for _, input := range []struct{ output, run, skip string }{
		{"ok package", "^Test", ""},
		{"TestIgnored", "^Test", "^TestIgnored$"},
		{"TestAlpha", "[", ""},
		{"TestAlpha", "^Test", "["},
	} {
		if _, _, _, err := shardTestPattern(input.output, input.run, input.skip, testShard{1, 1}); err == nil {
			t.Fatalf("accepted invalid or empty selection %+v", input)
		}
	}
}

func TestSingleShardAccountsForSelectionWithoutRewritingSubtests(t *testing.T) {
	for _, shard := range []string{"", "1/1"} {
		for _, command := range [][]string{
			{"go", "test", "./testdata/shards", "-run=^TestAlpha$/child", "-args", "-tnl-probe=kept"},
			{"go", "test", "./testdata/shards", "-run=^Test(Alpha|[/])$/child", "-skip=^TestAlpha$/other", "-args", "-tnl-probe=kept"},
			{"go", "test", "./testdata/shards", "-run=^Test[[:alpha:]/]+$/child", "-args", "-tnl-probe=kept"},
			{"go", "test", "./testdata/shards", "-args", "-tnl-probe=kept"},
		} {
			selected, err := shardGoTestCommand(t.Context(), ".", command, shard)
			if err != nil || !reflect.DeepEqual(selected, command) {
				t.Fatalf("single shard %q changed selection %v: %v, %v", shard, command, selected, err)
			}
		}
		command := []string{"go", "test", "./testdata/shards", "-run=^TestMissing$", "-args", "-tnl-probe=kept"}
		if _, err := shardGoTestCommand(t.Context(), ".", command, shard); err == nil {
			t.Fatalf("single shard %q accepted an empty selector", shard)
		}
	}
	if _, _, _, err := shardTestPattern("TestAlpha", "^Test", "Test/subtest", testShard{1, 4}); err == nil {
		t.Fatal("multiple shards accepted a subtest exclusion")
	}
}
