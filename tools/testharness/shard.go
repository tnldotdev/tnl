package main

import (
	"context"
	"errors"
	"fmt"
	"go/token"
	"hash/fnv"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type testShard struct {
	index int
	count int
}

func parseTestShard(value string) (testShard, error) {
	if value == "" {
		return testShard{index: 1, count: 1}, nil
	}
	indexText, countText, ok := strings.Cut(value, "/")
	index, indexErr := strconv.Atoi(indexText)
	count, countErr := strconv.Atoi(countText)
	if !ok || indexErr != nil || countErr != nil || count < 1 || count > 64 || index < 1 || index > count {
		return testShard{}, errors.New("-tnl-test-shard must be 1/N through N/N, with N between 1 and 64")
	}
	return testShard{index: index, count: count}, nil
}

// discover through Go itself so build constraints and newly added tests use the
// same inventory as execution. each complete top-level test belongs to one shard.
func shardGoTestCommand(ctx context.Context, root string, command []string, value string) ([]string, error) {
	shard, err := parseTestShard(value)
	if err != nil {
		return nil, err
	}
	if shard.count == 1 {
		return command, nil
	}
	if len(command) < 2 || command[0] != "go" || command[1] != "test" {
		return nil, errors.New("test sharding requires a go test command")
	}
	runIndex, run, err := goTestOption(command, "run")
	if err != nil {
		return nil, err
	}
	if runIndex == -1 || strings.Contains(run, "/") {
		return nil, errors.New("test sharding requires an explicit top-level -run expression")
	}
	_, skip, err := goTestOption(command, "skip")
	if err != nil {
		return nil, err
	}
	listIndex, _, err := goTestOption(command, "list")
	if err != nil {
		return nil, err
	}
	if listIndex != -1 {
		return nil, errors.New("test sharding cannot combine -run and -list")
	}
	listing := slices.Clone(command)
	if strings.Contains(listing[runIndex], "=") {
		listing[runIndex] = "-list=" + run
	} else {
		listing[runIndex] = "-list"
	}
	child := exec.CommandContext(ctx, listing[0], listing[1:]...)
	child.Dir, child.Stderr = root, os.Stderr
	output, err := child.Output()
	if err != nil {
		return nil, fmt.Errorf("discover tests for shard: %w", err)
	}
	pattern, selected, total, err := shardTestPattern(string(output), run, skip, shard)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "test shard %d/%d: %d of %d tests\n", shard.index, shard.count, selected, total)
	result := slices.Clone(command)
	if strings.Contains(result[runIndex], "=") {
		result[runIndex] = "-run=" + pattern
	} else {
		result[runIndex+1] = pattern
	}
	return result, nil
}

func goTestOption(command []string, name string) (int, string, error) {
	index, value := -1, ""
	for i := 2; i < len(command) && command[i] != "-args"; i++ {
		if command[i] != "-"+name && !strings.HasPrefix(command[i], "-"+name+"=") {
			continue
		}
		if index != -1 {
			return -1, "", fmt.Errorf("test sharding requires a single -%s option", name)
		}
		index = i
		if _, text, ok := strings.Cut(command[i], "="); ok {
			value = text
		} else if i+1 < len(command) && command[i+1] != "-args" {
			i++
			value = command[i]
		} else {
			return -1, "", fmt.Errorf("test sharding requires a value for -%s", name)
		}
	}
	return index, value, nil
}

func shardTestPattern(output, run, skip string, shard testShard) (string, int, int, error) {
	include, err := regexp.Compile(run)
	if err != nil {
		return "", 0, 0, fmt.Errorf("compile test shard -run: %w", err)
	}
	if strings.Contains(skip, "/") {
		return "", 0, 0, errors.New("test sharding requires a top-level -skip expression")
	}
	var exclude *regexp.Regexp
	if skip != "" {
		exclude, err = regexp.Compile(skip)
		if err != nil {
			return "", 0, 0, fmt.Errorf("compile test shard -skip: %w", err)
		}
	}
	var tests []string
	for line := range strings.SplitSeq(output, "\n") {
		if strings.HasPrefix(line, "Test") && token.IsIdentifier(line) && include.MatchString(line) && (exclude == nil || !exclude.MatchString(line)) {
			tests = append(tests, line)
		}
	}
	slices.Sort(tests)
	tests = slices.Compact(tests)
	var selected []string
	for _, name := range tests {
		hash := fnv.New32a()
		_, _ = hash.Write([]byte(name))
		if int(hash.Sum32()%uint32(shard.count))+1 == shard.index {
			selected = append(selected, regexp.QuoteMeta(name))
		}
	}
	if len(selected) == 0 {
		return "", 0, len(tests), fmt.Errorf("test shard %d/%d selected no tests out of %d", shard.index, shard.count, len(tests))
	}
	return "^(" + strings.Join(selected, "|") + ")$", len(selected), len(tests), nil
}
