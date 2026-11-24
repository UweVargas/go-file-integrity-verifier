// Package go_file_integrity_verifier streams file contents through hash
// functions and compares the resulting checksums against a manifest.
//
// The package is deliberately small: it exposes a Manifest type that can be
// parsed from a plain-text manifest file and a Verify function that checks a
// directory tree against that manifest. The manifest format is one entry per
// line:
//
//	<hex-checksum>  <relative-path>
//
// Two spaces separate the checksum from the path. Blank lines and lines whose
// first non-space character is '#' are ignored. The checksum is computed with
// SHA-256 by default because it is available in the standard library and has
// no practical collision concerns for file integrity work.
//
// The package intentionally does not walk subdirectories on its own. A caller
// that wants recursive verification can build a manifest with filepath.Walk
// and pass the resulting paths to Verify. Keeping the walk outside the package
// makes the behaviour explicit and keeps the core loop easy to test.
package go_file_integrity_verifier

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Manifest maps a relative file path to the lowercase hex SHA-256 checksum of
// the file contents.
type Manifest map[string]string

// Result describes the outcome of verifying a single manifest entry.
type Result struct {
	// Path is the relative path exactly as it appeared in the manifest.
	Path string
	// Expected is the checksum recorded in the manifest.
	Expected string
	// Actual is the checksum computed from the file on disk. It is empty when
	// the file could not be read.
	Actual string
	// Err is non-nil when the file could not be read or when the checksums
	// differ. A mismatch is reported through a sentinel error so callers can
	// distinguish it from I/O failures.
	Err error
}

// ErrMismatch is returned in Result.Err when a file's checksum does not match
// the manifest. Use errors.Is to test for it.
var ErrMismatch = errors.New("checksum mismatch")

// ParseManifest reads a manifest from r and returns the parsed entries. It
// returns an error if a line is malformed or if the same path appears twice.
// Duplicate paths are rejected because silently overwriting one entry would
// hide a corrupted manifest.
func ParseManifest(r io.Reader) (Manifest, error) {
	m := make(Manifest)
	scanner := bufio.NewScanner(r)
	// Allow paths long enough for deep directory trees without requiring the
	// caller to tune a buffer. The default 64 KiB limit is generous for paths
	// but we raise it to 1 MiB to avoid surprising failures on unusual inputs.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, "  ", 2)
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: expected '<checksum>  <path>'", lineNo)
		}
		sum := strings.TrimSpace(fields[0])
		path := strings.TrimSpace(fields[1])
		if sum == "" || path == "" {
			return nil, fmt.Errorf("line %d: empty checksum or path", lineNo)
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return nil, fmt.Errorf("line %d: checksum is not valid hex: %w", lineNo, err)
		}
		if _, exists := m[path]; exists {
			return nil, fmt.Errorf("line %d: duplicate path %q", lineNo, path)
		}
		m[path] = strings.ToLower(sum)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	return m, nil
}

// HashFile streams the file at path through h and returns the lowercase hex
// digest. The caller owns h and must not reuse it concurrently. The file is
// opened read-only and closed before returning.
func HashFile(path string, h hash.Hash) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h.Reset()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Verify checks every entry in m against the files rooted at dir. It returns
// one Result per manifest entry, in the order the entries were visited. The
// order is the map iteration order, which is not stable; callers that need a
// deterministic order should sort the returned slice by Path.
//
// A file that is missing or unreadable produces a Result with Err set to the
// underlying error. A file whose checksum differs produces a Result with Err
// set to ErrMismatch. Verify never returns a non-nil error itself; per-file
// problems are reported through Result.Err so that one bad file does not stop
// the rest of the check.
func Verify(dir string, m Manifest) []Result {
	results := make([]Result, 0, len(m))
	for path, expected := range m {
		res := Result{Path: path, Expected: expected}
		full := filepath.Join(dir, filepath.FromSlash(path))
		actual, err := HashFile(full, sha256.New())
		if err != nil {
			res.Err = err
			results = append(results, res)
			continue
		}
		res.Actual = actual
		if actual != expected {
			res.Err = ErrMismatch
		}
		results = append(results, res)
	}
	return results
}

// OK reports whether every result in rs passed. It is a convenience for the
// common case where the caller only cares about the overall outcome.
func OK(rs []Result) bool {
	for _, r := range rs {
		if r.Err != nil {
			return false
		}
	}
	return true
}
