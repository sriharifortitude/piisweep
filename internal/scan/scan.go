// Package scan walks files and streams their lines through the detectors.
package scan

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/sriharifortitude/piisweep/internal/detect"
)

const (
	// MaxLineBytes is the longest line read whole; a longer one is scanned in pieces of this
	// size, and a value split across two pieces can be missed.
	MaxLineBytes = 1 << 20
	// DefaultMaxBytes is how much of one file (after decompression) is read by default.
	DefaultMaxBytes = 1 << 30
)

// Options control a scan.
type Options struct {
	Min      detect.Confidence
	MaxBytes int64
	// Exclude holds glob patterns matched against each path's base name and slash form.
	Exclude []string
}

// Finding is a match with where it was found.
type Finding struct {
	Path   string `json:"path"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
	detect.Match
	Confidence string `json:"confidence"`
}

// Skipped records a file that was not scanned, or not scanned to the end, and why.
type Skipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Result is everything a scan found.
type Result struct {
	Findings []Finding `json:"findings"`
	// TestValues counts well-known example values, which are not findings.
	TestValues int       `json:"test_values"`
	Files      int       `json:"files_scanned"`
	Skipped    []Skipped `json:"skipped"`
}

// Paths scans files, directories (recursively) or "-" for standard input.
func Paths(paths []string, opt Options, stdin io.Reader) (*Result, error) {
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = DefaultMaxBytes
	}
	res := &Result{Findings: []Finding{}, Skipped: []Skipped{}}
	for _, p := range paths {
		if p == "-" {
			res.Files++
			if err := Reader("(stdin)", stdin, opt, res); err != nil {
				res.Skipped = append(res.Skipped, Skipped{"(stdin)", err.Error()})
			}
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, unwrap(err))
		}
		if !info.IsDir() {
			scanFile(p, opt, res)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				res.Skipped = append(res.Skipped, Skipped{filepath.ToSlash(path), unwrap(err).Error()})
				return nil
			}
			if d.IsDir() {
				if name := d.Name(); path != p && (name == ".git" || name == "node_modules" || excluded(path, opt.Exclude)) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || excluded(path, opt.Exclude) {
				return nil // symbolic links and devices are not followed
			}
			scanFile(path, opt, res)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func excluded(path string, patterns []string) bool {
	slash := filepath.ToSlash(path)
	base := filepath.Base(path)
	for _, pat := range patterns {
		if ok, _ := filepath.Match(pat, base); ok {
			return true
		}
		if ok, _ := filepath.Match(pat, slash); ok {
			return true
		}
		if strings.Contains(slash, "/"+strings.Trim(pat, "/")+"/") {
			return true
		}
	}
	return false
}

func unwrap(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

func scanFile(path string, opt Options, res *Result) {
	name := filepath.ToSlash(path)
	f, err := os.Open(path)
	if err != nil {
		res.Skipped = append(res.Skipped, Skipped{name, unwrap(err).Error()})
		return
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			res.Skipped = append(res.Skipped, Skipped{name, "not readable as gzip: " + err.Error()})
			return
		}
		defer gz.Close()
		r = gz
	}
	res.Files++
	if err := Reader(name, r, opt, res); err != nil {
		res.Skipped = append(res.Skipped, Skipped{name, err.Error()})
	}
}

var errBinary = errors.New("binary file, not scanned")

// Reader scans one stream line by line. It reads at most opt.MaxBytes. UTF-16 (with a byte
// order mark, or recognisable by its zero bytes) is decoded; anything else whose first 8 KiB
// is more than 1% zero bytes is treated as binary. A single stray NUL does not make a file
// binary: real source files contain them.
func Reader(name string, r io.Reader, opt Options, res *Result) error {
	limited := &io.LimitedReader{R: r, N: opt.MaxBytes}
	br := bufio.NewReaderSize(limited, 64*1024)
	head, _ := br.Peek(8192)
	if order := utf16Order(head); order != nil {
		br = bufio.NewReaderSize(&utf16Reader{src: br, order: order}, 64*1024)
	} else if bytes.Count(head, []byte{0}) > len(head)/100 {
		return errBinary
	}
	line := 1
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		buf = append(buf, chunk...)
		full := err == nil || err == io.EOF
		if errors.Is(err, bufio.ErrBufferFull) && len(buf) < MaxLineBytes {
			continue
		}
		if len(buf) > 0 {
			scanLine(name, line, buf, opt, res)
		}
		if full && len(chunk) > 0 && chunk[len(chunk)-1] == '\n' {
			line++
		}
		buf = buf[:0]
		if err == io.EOF {
			break
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return err
		}
	}
	if limited.N <= 0 {
		return fmt.Errorf("stopped after %d bytes (--max-bytes)", opt.MaxBytes)
	}
	return nil
}

// utf16Order returns the byte order of UTF-16 text, or nil when the bytes do not look like it.
func utf16Order(head []byte) []int {
	switch {
	case len(head) >= 2 && head[0] == 0xFF && head[1] == 0xFE:
		return []int{0, 1}
	case len(head) >= 2 && head[0] == 0xFE && head[1] == 0xFF:
		return []int{1, 0}
	}
	if len(head) < 16 {
		return nil
	}
	evenZero, oddZero := 0, 0
	for i := 0; i+1 < len(head); i += 2 {
		if head[i] == 0 {
			evenZero++
		}
		if head[i+1] == 0 {
			oddZero++
		}
	}
	pairs := len(head) / 2
	switch {
	case oddZero > pairs*9/10 && evenZero < pairs/10:
		return []int{0, 1} // ASCII-range text in little-endian UTF-16
	case evenZero > pairs*9/10 && oddZero < pairs/10:
		return []int{1, 0}
	}
	return nil
}

// utf16Reader turns UTF-16 into UTF-8. order[0] is the index of the low byte in each pair.
type utf16Reader struct {
	src   *bufio.Reader
	order []int
	out   []byte
	pend  []uint16
	bom   bool
}

func (u *utf16Reader) Read(p []byte) (int, error) {
	for len(u.out) == 0 {
		var pair [2]byte
		if _, err := io.ReadFull(u.src, pair[:]); err != nil {
			if len(u.pend) > 0 {
				u.out = utf8.AppendRune(u.out, utf8.RuneError)
				u.pend = nil
				break
			}
			if err == io.ErrUnexpectedEOF {
				err = io.EOF
			}
			return 0, err
		}
		v := uint16(pair[u.order[0]]) | uint16(pair[u.order[1]])<<8
		if !u.bom {
			u.bom = true
			if v == 0xFEFF {
				continue
			}
		}
		u.pend = append(u.pend, v)
		if utf16.IsSurrogate(rune(v)) && len(u.pend) == 1 {
			continue
		}
		for _, r := range utf16.Decode(u.pend) {
			u.out = utf8.AppendRune(u.out, r)
		}
		u.pend = u.pend[:0]
	}
	n := copy(p, u.out)
	u.out = u.out[n:]
	return n, nil
}

func scanLine(name string, line int, b []byte, opt Options, res *Result) {
	text := strings.TrimRight(string(b), "\r\n")
	for _, m := range detect.Find(text, opt.Min) {
		if m.TestValue {
			res.TestValues++
			continue
		}
		res.Findings = append(res.Findings, Finding{Path: name, Line: line, Column: m.Start + 1, Match: m,
			Confidence: m.Confidence.String()})
	}
}
