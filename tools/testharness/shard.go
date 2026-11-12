package main

import (
	"bytes"
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

// discover and execute the same compiled binaries, with no second go invocation.
func (p *preparedTests) selectShard(ctx context.Context, value string) error {
	shard, err := parseTestShard(value)
	if err != nil {
		return err
	}
	if shard.count > 1 && (!p.plan.explicitRun || strings.Contains(p.plan.run, "/")) {
		return errors.New("test sharding requires an explicit top-level -run expression")
	}
	// single-shard commands preserve subtest selection. discovery accounts for
	// their top-level parent; multiple shards always select complete tests.
	discoveryRun, discoverySkip := p.plan.run, p.plan.skip
	if shard.count == 1 {
		discoveryRun, _ = topLevelTestExpression(discoveryRun)
		if _, subtest := topLevelTestExpression(discoverySkip); subtest {
			discoverySkip = ""
		}
	}
	var inventory strings.Builder
	for _, binary := range p.binaries {
		arguments := append(slices.Clone(p.arguments), "-test.list="+discoveryRun)
		// -test.list ignores -test.skip; filtering belongs to shard selection.
		child := exec.Command(binary.path, arguments...)
		child.Dir = binary.directory
		var output bytes.Buffer
		child.Stdout, child.Stderr = &output, &output
		if err := runTestProcess(ctx, child); err != nil {
			return fmt.Errorf("discover tests for shard: %w\n%s", err, strings.TrimSpace(output.String()))
		}
		inventory.Write(output.Bytes())
		inventory.WriteByte('\n')
	}
	pattern, selected, total, err := shardTestPattern(inventory.String(), discoveryRun, discoverySkip, shard)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "test shard %d/%d: %d of %d tests\n", shard.index, shard.count, selected, total)
	if shard.count > 1 {
		p.arguments = append(p.arguments, "-test.run="+pattern)
	}
	return nil
}

// a level separator follows a complete expression, not an unfinished group,
// character class, or escape. let the regexp parser own those syntax details.
func topLevelTestExpression(pattern string) (string, bool) {
	for index, char := range pattern {
		if char == '/' {
			if _, err := regexp.Compile(pattern[:index]); err == nil {
				return pattern[:index], true
			}
		}
	}
	return pattern, false
}

func shardTestPattern(output, run, skip string, shard testShard) (string, int, int, error) {
	include, err := regexp.Compile(run)
	if err != nil {
		return "", 0, 0, fmt.Errorf("compile test shard -run: %w", err)
	}
	if shard.count > 1 && strings.Contains(skip, "/") {
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
