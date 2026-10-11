package scan

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/sriharifortitude/piisweep/internal/detect"
)

const iban = "DE44 5001 0517 5407 3249 31"

func opts() Options { return Options{Min: detect.Medium, MaxBytes: DefaultMaxBytes} }

func scanBytes(t *testing.T, data []byte, o Options) *Result {
	t.Helper()
	res := &Result{}
	if err := Reader("t", bytes.NewReader(data), o, res); err != nil {
		res.Skipped = append(res.Skipped, Skipped{"t", err.Error()})
	}
	return res
}

func write(t *testing.T, dir, rel string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLineAndColumn(t *testing.T) {
	res := scanBytes(t, []byte("first\r\nsecond\nrefund to "+iban+"\n"), opts())
	if len(res.Findings) != 1 || res.Findings[0].Line != 3 || res.Findings[0].Column != 11 {
		t.Fatalf("%+v", res.Findings)
	}
}

func utf16le(s string, bom bool) []byte {
	var b []byte
	if bom {
		b = append(b, 0xFF, 0xFE)
	}
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u), byte(u>>8))
	}
	return b
}

func TestUTF16IsDecoded(t *testing.T) {
	text := "Kontakt: hans.müller@posteo.de\r\nIBAN " + iban + "\r\n"
	for _, bom := range []bool{true, false} {
		res := scanBytes(t, utf16le(text, bom), opts())
		if len(res.Findings) != 2 || len(res.Skipped) != 0 || res.Findings[1].Line != 2 {
			t.Errorf("bom=%v: %+v %+v", bom, res.Findings, res.Skipped)
		}
	}
	// Big-endian with a byte order mark.
	var be []byte
	be = append(be, 0xFE, 0xFF)
	for _, u := range utf16.Encode([]rune("IBAN " + iban)) {
		be = append(be, byte(u>>8), byte(u))
	}
	if res := scanBytes(t, be, opts()); len(res.Findings) != 1 {
		t.Errorf("big-endian: %+v", res)
	}
}

func TestAStrayNULDoesNotMakeAFileBinary(t *testing.T) {
	data := []byte("join('\x00')\n" + strings.Repeat("ordinary source line\n", 50) + "IBAN " + iban + "\n")
	if res := scanBytes(t, data, opts()); len(res.Findings) != 1 || len(res.Skipped) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestBinaryIsSkipped(t *testing.T) {
	data := append(bytes.Repeat([]byte{0, 1, 2, 3, 0, 0, 7}, 400), []byte("IBAN "+iban)...)
	res := scanBytes(t, data, opts())
	if len(res.Findings) != 0 || len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0].Reason, "binary") {
		t.Fatalf("%+v", res)
	}
}

func TestMaxBytesStopsAndSaysSo(t *testing.T) {
	data := []byte(strings.Repeat("x\n", 100) + "IBAN " + iban + "\n")
	o := opts()
	o.MaxBytes = 50
	res := scanBytes(t, data, o)
	if len(res.Findings) != 0 || len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0].Reason, "max-bytes") {
		t.Fatalf("%+v", res)
	}
}

func TestAVeryLongLineIsScannedInPieces(t *testing.T) {
	long := strings.Repeat("a", MaxLineBytes+500) + " IBAN " + iban + "\nnext " + iban + "\n"
	res := scanBytes(t, []byte(long), opts())
	if len(res.Findings) != 2 || res.Findings[1].Line != 2 {
		t.Fatalf("%+v", res.Findings)
	}
}

func TestWellKnownTestValuesAreCountedNotReported(t *testing.T) {
	res := scanBytes(t, []byte("card 4111 1111 1111 1111\nIBAN DE89 3704 0044 0532 0130 00\n"), opts())
	if len(res.Findings) != 0 || res.TestValues != 2 {
		t.Fatalf("%+v", res)
	}
}

func TestDirectoryWalk(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.log", []byte("IBAN "+iban+"\n"))
	write(t, dir, "sub/old.log.gz", gz(t, "IBAN "+iban+"\n"))
	write(t, dir, ".git/objects/x", []byte("IBAN "+iban+"\n"))
	write(t, dir, "node_modules/x/readme.md", []byte("IBAN "+iban+"\n"))
	write(t, dir, "fixtures/data.csv", []byte("IBAN "+iban+"\n"))
	res, err := Paths([]string{dir}, Options{Min: detect.Medium, Exclude: []string{"fixtures"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range res.Findings {
		paths = append(paths, filepath.Base(f.Path))
	}
	if strings.Join(paths, ",") != "app.log,old.log.gz" || res.Files != 2 {
		t.Fatalf("%v files=%d", paths, res.Files)
	}
}

func gz(t *testing.T, s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestABrokenGzipIsReported(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "bad.gz", []byte("not gzip"))
	res, err := Paths([]string{dir}, opts(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0].Reason, "gzip") {
		t.Fatalf("%+v", res.Skipped)
	}
}

func TestExcludeByName(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.log", []byte("IBAN "+iban+"\n"))
	write(t, dir, "b.csv", []byte("IBAN "+iban+"\n"))
	res, err := Paths([]string{dir}, Options{Min: detect.Medium, Exclude: []string{"*.csv"}}, nil)
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestSymlinksAreNotFollowed(t *testing.T) {
	outside := write(t, t.TempDir(), "secret.log", []byte("IBAN "+iban+"\n"))
	dir := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "link.log")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	res, err := Paths([]string{dir}, opts(), nil)
	if err != nil || len(res.Findings) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestStdin(t *testing.T) {
	res, err := Paths([]string{"-"}, opts(), strings.NewReader("IBAN "+iban+"\n"))
	if err != nil || len(res.Findings) != 1 || res.Findings[0].Path != "(stdin)" {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestAMissingPathIsAnError(t *testing.T) {
	if _, err := Paths([]string{filepath.Join(t.TempDir(), "nope")}, opts(), nil); err == nil {
		t.Fatal("want an error")
	}
}

func TestAValueAcrossTheReadBufferBoundaryIsFound(t *testing.T) {
	// The reader's buffer is 64 KiB; a line longer than that is reassembled before scanning.
	line := strings.Repeat("a", 64*1024-12) + " " + iban + "\n"
	res := scanBytes(t, []byte(line), opts())
	if len(res.Findings) != 1 {
		t.Fatalf("%+v", res.Findings)
	}
}
