// Command gen writes the configuration JSON schema; see package
// schemagen. Run through go generate in package schema.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rom/xproxy/internal/config/schema/schemagen"
)

func main() {
	src := flag.String("src", "internal/config/config.go", "configuration source file")
	out := flag.String("out", "internal/config/schema/xproxy.schema.json", "output file")
	flag.Parse()
	b, err := schemagen.Generate(*src)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil { //nolint:gosec // documentation file
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
