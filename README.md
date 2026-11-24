# go-file-integrity-verifier

Streams file contents through SHA-256 and compares the resulting checksums
against a plain-text manifest so you can detect corruption or tampering.

## Usage

```go
package main

import (
	"fmt"
	"os"
	"strings"

	giv "go-file-integrity-verifier"
)

func main() {
	manifestText := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  hello.txt\n"
	m, err := giv.ParseManifest(strings.NewReader(manifestText))
	if err != nil {
		panic(err)
	}

	results := giv.Verify("./data", m)
	for _, r := range results {
		if r.Err != nil {
			fmt.Printf("%s: %v\n", r.Path, r.Err)
			continue
		}
		fmt.Printf("%s: ok\n", r.Path)
	}
	if !giv.OK(results) {
		os.Exit(1)
	}
}
```

The manifest format is one entry per line, `<hex-sha256>  <relative-path>`,
with two spaces between the checksum and the path. Blank lines and lines
starting with `#` are ignored. Checksums are compared case-insensitively.

## Why this exists

The problem is narrow: a directory of files and a manifest of expected
SHA-256 digests. The library parses the manifest, streams each file through
`crypto/sha256`, and reports per-file results. The trade-off is that the
library does not walk directories for you. Recursive discovery is a policy
decision (do you follow symlinks? skip hidden files? handle unreadable
directories?) and baking one policy into the core would make the package
harder to use for anyone who wanted a different one. Callers build the
manifest with `filepath.Walk` and pass the paths in.

## The awkward edge

`Verify` returns one `Result` per manifest entry, but map iteration order in
Go is not stable, so the slice order is not deterministic. If you need a
stable order (for diffing two runs, for example), sort the slice by `Path`
before comparing. A missing file is reported through `Result.Err` as an I/O
error; a present file whose checksum differs is reported through
`Result.Err` as `ErrMismatch`. Use `errors.Is(err, giv.ErrMismatch)` to tell
the two apart.
