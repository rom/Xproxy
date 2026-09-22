// Command covergate enforces statement coverage from a Go cover profile:
// a minimum for the core packages as a whole and a floor per package, so
// a regression in one package cannot hide behind the total.
//
//	go test -race -coverprofile=coverage.out -covermode=atomic ./...
//	go run ./test/covergate -profile coverage.out -min 80 -floor 60
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Packages outside the gate: test helpers and fakes, generated or
// trivial packages.
//
// Binaries are excluded by where they live rather than by name: every
// main package in this repository is under a cmd directory, the
// released ones under the top level cmd/ and the go:generate helpers
// under a cmd/ beside the package they generate for. A main package is
// a flag parse and an error print over a package that is gated on its
// own, and listing each one is a list that goes stale silently — the
// gate simply stops failing to mention the newest generator.
var excluded = []string{
	// The sandbox applies Landlock and seccomp to a confined child process
	// in its tests; the profile of the parent cannot see that code run.
	"github.com/rom/xproxy/internal/sandbox",
	"github.com/rom/xproxy/test/",
	"github.com/rom/xproxy/internal/acme/acmetest",
	"github.com/rom/xproxy/internal/icap/icaptest",
	"github.com/rom/xproxy/internal/filter/filtertest",
	"github.com/rom/xproxy/internal/testutil",
	"github.com/rom/xproxy/internal/version",
	"github.com/rom/xproxy/internal/filters", // registration list only (subpackages are gated)
}

type block struct{ stmts, count int }

func main() {
	profile := flag.String("profile", "coverage.out", "cover profile")
	minTotal := flag.Float64("min", 80, "minimum coverage of the core packages together, percent")
	floor := flag.Float64("floor", 60, "minimum coverage of any single core package, percent")
	flag.Parse()
	os.Exit(run(*profile, *minTotal, *floor))
}

func run(profile string, minTotal, floor float64) int {
	f, err := os.Open(profile) //nolint:gosec // operator supplied path
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer func() { _ = f.Close() }()
	// Blocks are keyed by position so that the same block reported by
	// several test binaries (the profile of ./... concatenates them) is
	// counted once, with its highest count.
	blocks := map[string]map[string]block{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "mode:") || line == "" {
			continue
		}
		file, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) != 3 {
			continue
		}
		stmts, _ := strconv.Atoi(fields[1])
		count, _ := strconv.Atoi(fields[2])
		pkg := file[:strings.LastIndex(file, "/")]
		if blocks[pkg] == nil {
			blocks[pkg] = map[string]block{}
		}
		key := file + ":" + fields[0]
		if b, seen := blocks[pkg][key]; !seen || count > b.count {
			blocks[pkg][key] = block{stmts: stmts, count: count}
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	type row struct {
		pkg     string
		percent float64
		stmts   int
	}
	rows := make([]row, 0, len(blocks))
	var totalStmts, coveredStmts int
	for pkg, bs := range blocks {
		if isExcluded(pkg) {
			continue
		}
		var s, c int
		for _, b := range bs {
			s += b.stmts
			if b.count > 0 {
				c += b.stmts
			}
		}
		if s == 0 {
			continue
		}
		rows = append(rows, row{pkg: strings.TrimPrefix(pkg, "github.com/rom/xproxy/"), percent: 100 * float64(c) / float64(s), stmts: s})
		totalStmts += s
		coveredStmts += c
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].percent > rows[j].percent })
	failed := false
	for _, r := range rows {
		mark := "  "
		if r.percent < floor {
			mark = "!!"
			failed = true
		}
		fmt.Printf("%s %5.1f%%  %-28s (%d statements)\n", mark, r.percent, r.pkg, r.stmts)
	}
	total := 100 * float64(coveredStmts) / float64(max(totalStmts, 1))
	fmt.Printf("\ncore packages: %.1f%% of %d statements (gate %.0f%%, per package floor %.0f%%)\n", total, totalStmts, minTotal, floor)
	if total < minTotal {
		fmt.Printf("FAIL: total below %.0f%%\n", minTotal)
		failed = true
	}
	if failed {
		return 1
	}
	fmt.Println("OK")
	return 0
}

func isExcluded(pkg string) bool {
	// A main package: cmd/ at the top level or beside what it generates.
	if strings.HasPrefix(pkg, "github.com/rom/xproxy/cmd/") || strings.Contains(pkg, "/cmd/") {
		return true
	}
	for _, e := range excluded {
		if strings.HasSuffix(e, "/") {
			if strings.HasPrefix(pkg, e) {
				return true
			}
		} else if pkg == e {
			return true
		}
	}
	return false
}
