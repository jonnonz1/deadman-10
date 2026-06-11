package main

import (
	"os"
	"slices"
	"strings"

	"github.com/jonnonz1/deadman-10/internal/config"
	"github.com/jonnonz1/deadman-10/internal/release"
)

// hasFlag reports whether name appears anywhere in the arguments.
func hasFlag(name string) bool {
	return slices.Contains(os.Args[2:], name)
}

// flagValue returns the value for name, accepting both "--name value" and
// "--name=value" forms, or "" if absent.
func flagValue(name string) string {
	for i, a := range os.Args {
		if a == name && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
		if v, ok := strings.CutPrefix(a, name+"="); ok {
			return v
		}
	}
	return ""
}

// must aborts on error.
func must(err error) {
	if err != nil {
		fail(err)
	}
}

// fileExists reports whether path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// readFile returns a file's contents as a string, aborting on error.
func readFile(path string) string {
	b, err := os.ReadFile(path)
	must(err)
	return string(b)
}

// readLines returns non-empty, non-comment lines from a file.
func readLines(path string) []string {
	var out []string
	for line := range strings.SplitSeq(readFile(path), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// releaserFor builds a Releaser over the configured vault, publisher, notifier.
func releaserFor(cfg *config.Config, root string, pub release.Publisher, notifier release.Notifier) *release.Releaser {
	return release.New(abs(root, cfg.VaultPath), pub, notifier)
}
