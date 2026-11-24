package go_file_integrity_verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile is a tiny helper that keeps the tests readable. It fails the test
// immediately on any error because a setup failure is never the behaviour
// under test.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", full, err)
	}
	return full
}

// sha256Hex is used to build expected manifests without duplicating the
// production hashing path.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestParseManifestValid(t *testing.T) {
	input := "# comment\n" +
		"\n" +
		"abc123  a.txt\n" +
		"  DEF456  sub/b.txt  \n"
	m, err := ParseManifest(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if len(m) != 2 {
		t.Fatalf("got %d entries, want 2", len(m))
	}
	if got := m["a.txt"]; got != "abc123" {
		t.Errorf("a.txt = %q, want abc123", got)
	}
	// Checksums are normalised to lowercase so comparisons are case-insensitive.
	if got := m["sub/b.txt"]; got != "def456" {
		t.Errorf("sub/b.txt = %q, want def456", got)
	}
}

func TestParseManifestRejectsMalformed(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"missing separator", "abc123 a.txt\n"},
		{"empty checksum", "  a.txt\n"},
		{"empty path", "abc123  \n"},
		{"non-hex checksum", "xyz123  a.txt\n"},
		{"duplicate path", "abc123  a.txt\nabc123  a.txt\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseManifest(strings.NewReader(tc.input)); err == nil {
				t.Fatalf("ParseManifest(%q) = nil error, want error", tc.input)
			}
		})
	}
}

func TestParseManifestEmptyInput(t *testing.T) {
	m, err := ParseManifest(strings.NewReader(""))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("got %d entries, want 0", len(m))
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "hello world\n")
	got, err := HashFile(filepath.Join(dir, "a.txt"), sha256.New())
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	want := sha256Hex("hello world\n")
	if got != want {
		t.Errorf("HashFile = %q, want %q", got, want)
	}
}

func TestHashFileMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := HashFile(filepath.Join(dir, "nope.txt"), sha256.New())
	if err == nil {
		t.Fatal("HashFile on missing file = nil error, want error")
	}
}

func TestVerifyAllMatch(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "alpha")
	writeFile(t, dir, "b.txt", "bravo")
	m := Manifest{
		"a.txt": sha256Hex("alpha"),
		"b.txt": sha256Hex("bravo"),
	}
	rs := Verify(dir, m)
	if len(rs) != 2 {
		t.Fatalf("got %d results, want 2", len(rs))
	}
	if !OK(rs) {
		t.Fatalf("OK = false, results: %+v", rs)
	}
	for _, r := range rs {
		if r.Err != nil {
			t.Errorf("%s: unexpected error %v", r.Path, r.Err)
		}
		if r.Actual == "" {
			t.Errorf("%s: empty actual checksum", r.Path)
		}
	}
}

func TestVerifyMismatch(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "alpha")
	m := Manifest{"a.txt": sha256Hex("something else")}
	rs := Verify(dir, m)
	if len(rs) != 1 {
		t.Fatalf("got %d results, want 1", len(rs))
	}
	if !errors.Is(rs[0].Err, ErrMismatch) {
		t.Fatalf("Err = %v, want ErrMismatch", rs[0].Err)
	}
	if rs[0].Actual != sha256Hex("alpha") {
		t.Errorf("Actual = %q, want %q", rs[0].Actual, sha256Hex("alpha"))
	}
	if OK(rs) {
		t.Fatal("OK = true, want false")
	}
}

func TestVerifyMissingFile(t *testing.T) {
	dir := t.TempDir()
	m := Manifest{"missing.txt": sha256Hex("whatever")}
	rs := Verify(dir, m)
	if len(rs) != 1 {
		t.Fatalf("got %d results, want 1", len(rs))
	}
	if rs[0].Err == nil {
		t.Fatal("Err = nil, want error")
	}
	if errors.Is(rs[0].Err, ErrMismatch) {
		t.Fatal("Err = ErrMismatch, want an I/O error")
	}
	if rs[0].Actual != "" {
		t.Errorf("Actual = %q, want empty", rs[0].Actual)
	}
}

func TestVerifySubdirectoryPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "sub"), "b.txt", "nested")
	m := Manifest{"sub/b.txt": sha256Hex("nested")}
	rs := Verify(dir, m)
	if len(rs) != 1 {
		t.Fatalf("got %d results, want 1", len(rs))
	}
	if rs[0].Err != nil {
		t.Fatalf("unexpected error: %v", rs[0].Err)
	}
}

func TestVerifyEmptyManifest(t *testing.T) {
	rs := Verify(t.TempDir(), Manifest{})
	if len(rs) != 0 {
		t.Fatalf("got %d results, want 0", len(rs))
	}
	if !OK(rs) {
		t.Fatal("OK(empty) = false, want true")
	}
}

func TestOKDetectsAnyFailure(t *testing.T) {
	if OK(nil) != true {
		t.Fatal("OK(nil) = false, want true")
	}
	rs := []Result{
		{Path: "a", Err: nil},
		{Path: "b", Err: ErrMismatch},
	}
	if OK(rs) {
		t.Fatal("OK with one mismatch = true, want false")
	}
}
