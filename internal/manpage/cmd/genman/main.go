// Command genman writes the manual pages under docs/man from the
// repository's Markdown; see package manpage. Run through go generate.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rom/xproxy/internal/manpage"
)

func main() {
	docs := flag.String("docs", "docs", "documentation directory")
	flag.Parse()
	pages, err := manpage.Build(*docs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for name, content := range pages {
		if err := os.WriteFile(filepath.Join(*docs, "man", name), content, 0o644); err != nil { //nolint:gosec // documentation
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
