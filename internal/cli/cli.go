// Package cli is piisweep's command line.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sriharifortitude/piisweep/internal/detect"
	"github.com/sriharifortitude/piisweep/internal/scan"
)

// Version is the release.
var Version = "0.1.0"

const usage = `piisweep: find personal data in logs, exports and test fixtures.

usage: piisweep [flags] PATH...

PATH is a file, a directory (searched recursively; .git and node_modules are skipped),
or - for standard input. Files ending in .gz are decompressed.

flags:
  --min-confidence L   report matches at least this confident: low, medium (default), high
  --json               machine-readable output
  --exclude GLOB       skip matching files or directories; repeatable
  --max-bytes N        read at most N bytes of each file, after decompression (default 1 GiB)
  --summary            print only the counts per kind
  --version

Values are always shown masked. Well-known example values (test card numbers, the IBANs
banks publish as examples) are counted, not reported.

exit status: 0 nothing found, 1 personal data found, 2 usage error or unreadable path
`

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// Run executes the command and returns the exit status.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("piisweep", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	minConf := fs.String("min-confidence", "medium", "")
	asJSON := fs.Bool("json", false, "")
	summary := fs.Bool("summary", false, "")
	maxBytes := fs.Int64("max-bytes", scan.DefaultMaxBytes, "")
	version := fs.Bool("version", false, "")
	help := fs.Bool("help", false, "")
	var exclude multi
	fs.Var(&exclude, "exclude", "")

	var paths []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			fmt.Fprintf(stderr, "piisweep: %v\n\n%s", err, usage)
			return 2
		}
		rest = fs.Args()
		if len(rest) > 0 {
			if rest[0] == "--" {
				paths = append(paths, rest[1:]...)
				break
			}
			paths = append(paths, rest[0])
			rest = rest[1:]
		}
	}
	switch {
	case *help:
		fmt.Fprint(stdout, usage)
		return 0
	case *version:
		fmt.Fprintf(stdout, "piisweep %s\n", Version)
		return 0
	case len(paths) == 0:
		fmt.Fprint(stderr, usage)
		return 2
	}
	min, ok := detect.ParseConfidence(*minConf)
	if !ok {
		fmt.Fprintf(stderr, "piisweep: --min-confidence must be low, medium or high, not %q\n", *minConf)
		return 2
	}
	if *maxBytes <= 0 {
		fmt.Fprintln(stderr, "piisweep: --max-bytes must be positive")
		return 2
	}

	res, err := scan.Paths(paths, scan.Options{Min: min, MaxBytes: *maxBytes, Exclude: exclude}, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "piisweep: %v\n", err)
		return 2
	}

	switch {
	case *asJSON:
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(stderr, "piisweep: %v\n", err)
			return 2
		}
	default:
		if !*summary {
			for _, f := range res.Findings {
				also := ""
				if len(f.Also) > 0 {
					also = " (also valid as " + strings.Join(f.Also, ", ") + ")"
				}
				fmt.Fprintf(stdout, "%s:%d:%d  %s %-6s %s  %s%s\n", f.Path, f.Line, f.Column, f.ID, f.Confidence, f.Kind, f.Masked, also)
			}
			for _, s := range res.Skipped {
				fmt.Fprintf(stdout, "%s: skipped: %s\n", s.Path, s.Reason)
			}
		}
		fmt.Fprint(stdout, Summary(res))
	}
	if len(res.Findings) > 0 {
		return 1
	}
	return 0
}

// Summary is the closing count, by kind.
func Summary(res *scan.Result) string {
	var b strings.Builder
	counts := map[string]int{}
	for _, f := range res.Findings {
		counts[f.ID+" "+f.Kind]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(&b, "%d finding(s) in %d file(s) scanned", len(res.Findings), res.Files)
	if res.TestValues > 0 {
		fmt.Fprintf(&b, "; %d well-known test value(s) not counted", res.TestValues)
	}
	b.WriteByte('\n')
	for _, k := range keys {
		fmt.Fprintf(&b, "  %5d  %s\n", counts[k], k)
	}
	return b.String()
}
