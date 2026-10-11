package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Values that must never appear in output, in any format.
var raw = []string{"DE44500105175407324931", "DE44 5001 0517 5407 3249 31", "4532015112830366", "4532 0151 1283 0366",
	"alice.martin@posteo.de", "86095742719"}

const sample = "user alice.martin@posteo.de paid 4532 0151 1283 0366\nrefund DE44 5001 0517 5407 3249 31\nSteuer-ID 86095742719\n"

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestFindingsExitOneAndAreMasked(t *testing.T) {
	for _, mode := range [][]string{{}, {"--json"}, {"--summary"}, {"--min-confidence", "low"}} {
		code, out, _ := run(t, sample, append([]string{"-"}, mode...)...)
		if code != 1 {
			t.Errorf("%v: exit %d", mode, code)
		}
		for _, r := range raw {
			if strings.Contains(out, r) {
				t.Errorf("%v: output contains the raw value %q:\n%s", mode, r, out)
			}
		}
	}
}

func TestCleanInputExitsZero(t *testing.T) {
	code, out, _ := run(t, "GET /index.html 200\n", "-")
	if code != 0 || !strings.HasPrefix(out, "0 finding(s)") {
		t.Fatalf("%d %q", code, out)
	}
}

func TestJSON(t *testing.T) {
	_, out, _ := run(t, sample, "-", "--json")
	var res struct {
		Findings []struct {
			ID, Kind, Masked, Confidence, Path string
			Line, Column                       int
		} `json:"findings"`
		Files int `json:"files_scanned"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(res.Findings) != 4 || res.Files != 1 || res.Findings[0].Masked == "" || res.Findings[0].Line != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestHighOnly(t *testing.T) {
	_, out, _ := run(t, "ref 4532015112830366\nIBAN DE44 5001 0517 5407 3249 31\n", "-", "--min-confidence", "high")
	if strings.Contains(out, "PI003") || !strings.Contains(out, "PI002") {
		t.Fatalf("%s", out)
	}
}

func TestUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no paths":       {},
		"bad confidence": {"--min-confidence", "extreme", "-"},
		"bad max bytes":  {"--max-bytes", "0", "-"},
		"unknown flag":   {"--nope", "-"},
		"missing file":   {filepath.Join(os.TempDir(), "piisweep-does-not-exist.log")},
	} {
		if code, _, errOut := run(t, "", args...); code != 2 || errOut == "" {
			t.Errorf("%s: %d %q", name, code, errOut)
		}
	}
}

func TestFlagsAfterPaths(t *testing.T) {
	code, out, _ := run(t, sample, "-", "--summary")
	if code != 1 || strings.Contains(out, ":1:") {
		t.Fatalf("%d %s", code, out)
	}
}

func TestVersionAndHelp(t *testing.T) {
	if code, out, _ := run(t, "", "--version"); code != 0 || !strings.HasPrefix(out, "piisweep ") {
		t.Fatal(out)
	}
	if code, out, _ := run(t, "", "--help"); code != 0 || !strings.Contains(out, "usage:") {
		t.Fatal(out)
	}
}
