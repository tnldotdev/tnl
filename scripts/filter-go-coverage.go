//go:build ignore

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		fatalf("usage: go run scripts/filter-go-coverage.go INPUT OUTPUT")
	}
	modulePath, err := readModulePath("go.mod")
	if err != nil {
		fatalf("read module path: %v", err)
	}
	input, err := os.Open(os.Args[1])
	if err != nil {
		fatalf("open coverage profile: %v", err)
	}
	defer input.Close()
	output, err := os.Create(os.Args[2])
	if err != nil {
		fatalf("create filtered coverage profile: %v", err)
	}

	generated := make(map[string]bool)
	excluded := make(map[string]struct{})
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "mode: ") {
			if _, err = fmt.Fprintln(output, line); err != nil {
				fatalf("write filtered coverage profile: %v", err)
			}
			continue
		}
		filename, _, found := strings.Cut(line, ":")
		if !found {
			fatalf("invalid coverage profile line %q", line)
		}
		isGenerated, known := generated[filename]
		if !known {
			isGenerated, err = generatedFile(filename, modulePath)
			if err != nil {
				fatalf("inspect %s: %v", filename, err)
			}
			generated[filename] = isGenerated
		}
		if isGenerated {
			excluded[filename] = struct{}{}
			continue
		}
		if _, err = fmt.Fprintln(output, line); err != nil {
			fatalf("write filtered coverage profile: %v", err)
		}
	}
	if err := scanner.Err(); err != nil {
		fatalf("read coverage profile: %v", err)
	}
	if err := output.Close(); err != nil {
		fatalf("close filtered coverage profile: %v", err)
	}
	summary, err := exec.Command("go", "tool", "cover", "-func="+os.Args[2]).Output()
	if err != nil {
		fatalf("summarize filtered coverage profile: %v", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(summary)))
	if len(fields) == 0 {
		fatalf("coverage summary was empty")
	}
	fmt.Printf("Go coverage: %s of statements (%d generated files excluded)\n", fields[len(fields)-1], len(excluded))
}

func readModulePath(name string) (string, error) {
	file, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if modulePath, found := strings.CutPrefix(strings.TrimSpace(scanner.Text()), "module "); found {
			return strings.TrimSpace(modulePath), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("module directive not found")
}

func generatedFile(name, modulePath string) (bool, error) {
	relative, found := strings.CutPrefix(name, modulePath+"/")
	if !found {
		return false, nil
	}
	file, err := os.Open(filepath.FromSlash(relative))
	if err != nil {
		return false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "package ") {
			return false, nil
		}
		if strings.HasPrefix(line, "// Code generated ") && strings.HasSuffix(line, " DO NOT EDIT.") {
			return true, nil
		}
	}
	return false, scanner.Err()
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
