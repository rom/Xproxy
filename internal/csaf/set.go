package csaf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The loaded advisories, and where they come from.
//
// A source is a directory or a file on disk, and that is the whole list. There
// is no fetch here, deliberately:
//
//   - The estate this is for keeps its process network away from the internet,
//     and a relay that dialled a vendor's website every hour would be a second
//     network dependency in the one place that is supposed to have none. An OT
//     change board would refuse it, and would be right to.
//   - Advisory distribution already has downloaders. The CSAF standard defines
//     one, every vendor in scope publishes a ROLIE feed or a directory
//     listing, and a cron job on a machine that is allowed out writes the
//     documents where this can read them. That machine is also where the
//     signature checking belongs -- CSAF documents are published with
//     detached signatures, and verifying one is not something this package
//     should be inventing.
//
// What it does hold to is the rule the imported-list package beside it holds
// to, for the same reason: **a source that cannot be read at load is a load
// error.** A proxy that came up reporting nothing because a directory was
// misspelled would be a proxy quietly claiming an estate has no advisories
// against it. On a *refresh*, the opposite: a failure keeps what is already
// loaded and is counted, because a directory being rewritten must not empty the
// assessment.

// Bounds on a set.
const (
	// MaxDocuments bounds the advisories one set holds. A vendor's whole
	// published history is a few thousand documents; a directory past this is
	// one nobody curated, and the bound is reported rather than silently
	// applied.
	MaxDocuments = 8192
	// MaxSetRecords bounds the (vulnerability, product) records across the
	// whole set, which is what a match walks.
	MaxSetRecords = 1 << 20
	// MaxFilesPerSource bounds the files one directory may yield.
	MaxFilesPerSource = 16384
)

// Source is one place advisories come from.
type Source struct {
	// Name is what an operator called it: "siemens-productcert", "cisa-ics".
	// It is carried into the status view so that a stale directory is
	// attributable.
	Name string
	// File is one document, and Directory a directory of them. Exactly one is
	// set.
	File, Directory string
}

// Options configure a set.
type Options struct {
	// Now is the clock, for tests.
	Now func() time.Time
}

// Set is the loaded advisories, indexed for matching.
type Set struct {
	mu sync.RWMutex
	// advisories is every document, in the order they were read.
	advisories []*Advisory
	// bySource is the documents each source yielded, kept so that a source
	// that fails a refresh keeps the documents it last gave rather than
	// disappearing from the set: a directory being rewritten must not empty
	// the part of the assessment that came from it.
	bySource map[string][]*Advisory
	// postings maps a product-name token to the records whose product or
	// platform name contains it. A match needs at least one token in common --
	// containment in either direction guarantees that -- so the postings for a
	// device's own tokens are the only records worth comparing it against.
	postings map[string][]ref
	// sources is what was read, with the per-source counts.
	sources []SourceStatus
	// records and skipped are the totals.
	records, skipped int
	loaded           time.Time
	now              func() time.Time
	// Assessments counts the devices assessed against this set, and Affected
	// how many of those came back affected.
	Assessments, Affected atomic.Uint64
}

// ref is one record of one advisory.
type ref struct {
	adv *Advisory
	rec int
}

// candidate is what a match walks.
type candidate struct {
	adv *Advisory
	rec Record
}

// SourceStatus is one source, for the status view: what it is, what it
// yielded, and what went wrong.
type SourceStatus struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Documents int    `json:"documents"`
	Records   int    `json:"records"`
	// Ignored counts files in a directory that are not CSAF documents at all
	// -- an index, a provider-metadata file, a signature, a README. Ordinary,
	// and counted so that a directory of the wrong thing is visible.
	Ignored int `json:"ignored"`
	// Failures counts documents that are CSAF and would not read. At load
	// these are the error; on a refresh they are counted and the previous
	// documents kept.
	Failures int       `json:"failures"`
	Error    string    `json:"error,omitempty"`
	Read     time.Time `json:"read"`
}

// Counts is the whole set, for the status view.
type Counts struct {
	Documents   int            `json:"documents"`
	Records     int            `json:"records"`
	Skipped     int            `json:"skipped"`
	Loaded      time.Time      `json:"loaded"`
	Sources     []SourceStatus `json:"sources"`
	Assessments uint64         `json:"assessments"`
	Affected    uint64         `json:"affected"`
}

// Load reads every source. A source that cannot be read is an error and no set
// is returned: at start there is nothing to keep, and a set that is empty
// because a path was wrong is worse than no set at all.
func Load(sources []Source, o Options) (*Set, error) {
	s := &Set{now: o.Now}
	if s.now == nil {
		s.now = time.Now
	}
	if len(sources) == 0 {
		return nil, errors.New("csaf: no sources")
	}
	if err := s.reload(sources, true); err != nil {
		return nil, err
	}
	return s, nil
}

// Refresh re-reads every source. A source that fails keeps what the set
// already holds, and the failure is counted and returned so that a caller can
// log it: a set that has quietly stopped updating is the failure worth
// reporting.
func (s *Set) Refresh(sources []Source) error { return s.reload(sources, false) }

// reload does the reading. Everything is built outside the lock and swapped in,
// so a refresh never leaves a matcher looking at half a set.
func (s *Set) reload(sources []Source, first bool) error {
	var (
		docs     []*Advisory
		records  int
		skipped  int
		firstErr error
	)
	statuses := make([]SourceStatus, 0, len(sources))
	s.mu.RLock()
	previous := s.bySource
	s.mu.RUnlock()
	kept := make(map[string][]*Advisory, len(sources))
	for _, src := range sources {
		st := SourceStatus{Name: src.Name, Path: src.File + src.Directory, Read: s.now()}
		found, err := read(src, &st)
		if err != nil {
			st.Error = err.Error()
			st.Failures++
			if first {
				return fmt.Errorf("csaf source %s: %w", src.Name, err)
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("csaf source %s: %w", src.Name, err)
			}
			// The documents this source gave last time are kept, which is the
			// whole rule on a refresh: a directory being rewritten, or a
			// mount that went away for a minute, must not empty the part of
			// the assessment that came from it. What changes is that the
			// failure is counted and the source's own status carries it, so a
			// set that has quietly stopped updating is visible as itself.
			found = previous[src.Name]
			st.Read = time.Time{}
		}
		var mine []*Advisory
		for _, a := range found {
			if len(docs) >= MaxDocuments || records+len(a.Records) > MaxSetRecords {
				st.Ignored++
				skipped += len(a.Records)
				continue
			}
			docs = append(docs, a)
			mine = append(mine, a)
			records += len(a.Records)
			skipped += a.Skipped
			st.Documents++
			st.Records += len(a.Records)
		}
		kept[src.Name] = mine
		statuses = append(statuses, st)
	}
	postings := index(docs)
	s.mu.Lock()
	s.advisories, s.postings, s.sources, s.bySource = docs, postings, statuses, kept
	s.records, s.skipped, s.loaded = records, skipped, s.now()
	s.mu.Unlock()
	return firstErr
}

// index builds the postings list.
func index(docs []*Advisory) map[string][]ref {
	out := map[string][]ref{}
	for _, a := range docs {
		for i := range a.Records {
			seen := map[string]bool{}
			for _, name := range [2]string{a.Records[i].Product, a.Records[i].Platform} {
				for _, t := range tokensOf(name) {
					if seen[t] {
						continue
					}
					seen[t] = true
					out[t] = append(out[t], ref{adv: a, rec: i})
				}
			}
		}
	}
	return out
}

// read reads one source.
func read(src Source, st *SourceStatus) ([]*Advisory, error) {
	switch {
	case src.File != "" && src.Directory != "":
		return nil, errors.New("both a file and a directory")
	case src.File != "":
		a, err := readFile(src.File)
		if err != nil {
			if errors.Is(err, ErrNotCSAF) {
				// A file named directly is a file somebody meant: it not being
				// an advisory is an error rather than something to skip.
				return nil, fmt.Errorf("%s: %w", src.File, err)
			}
			return nil, err
		}
		return []*Advisory{a}, nil
	case src.Directory != "":
		return readDir(src.Directory, st)
	}
	return nil, errors.New("neither a file nor a directory")
}

// readFile reads one document.
func readFile(path string) (*Advisory, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s: is a directory", path)
	}
	// The bound before the read, not after: a file that is a terabyte would
	// otherwise be this process's memory bound.
	if info.Size() > MaxDocumentBytes {
		return nil, fmt.Errorf("%s: %d bytes, past the %d-byte bound",
			path, info.Size(), MaxDocumentBytes)
	}
	body, err := os.ReadFile(path) //nolint:gosec // an operator named this path
	if err != nil {
		return nil, err
	}
	a, err := Parse(body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	a.File = path
	return a, nil
}

// readDir reads a directory of documents.
//
// It walks subdirectories, because every publisher's distribution puts the
// documents in a directory per year. What it does not do is follow symbolic
// links out of the tree, and a file it cannot read *as an advisory* is one of
// two things: not CSAF at all, which is counted and ignored, or CSAF that will
// not parse, which is a failure and is reported.
func readDir(dir string, st *SourceStatus) ([]*Advisory, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s: not a directory", dir)
	}
	var out []*Advisory
	var files int
	var firstErr error
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			// A symbolic link in an advisory directory is a file this process
			// would read from wherever it points, which is not what a
			// directory of documents is for.
			st.Ignored++
			return nil
		}
		if !strings.EqualFold(filepath.Ext(p), ".json") {
			// Everything a distribution puts beside the documents: the
			// signatures, the checksums, the index, the changes file.
			st.Ignored++
			return nil
		}
		if files >= MaxFilesPerSource {
			return fmt.Errorf("%s: more than %d files", dir, MaxFilesPerSource)
		}
		files++
		a, err := readFile(p)
		switch {
		case errors.Is(err, ErrNotCSAF):
			st.Ignored++
			return nil
		case err != nil:
			st.Failures++
			if firstErr == nil {
				firstErr = err
			}
			return nil
		}
		out = append(out, a)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if firstErr != nil {
		// A document that is CSAF and will not parse is a document somebody
		// published and this cannot read. It is the error even when the rest
		// of the directory read, because the alternative is an assessment
		// that silently omits an advisory.
		return out, firstErr
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no CSAF documents (%d files ignored)", dir, st.Ignored)
	}
	return out, nil
}

// candidates are the records worth comparing a device against: the ones
// sharing at least one product-name token with it.
//
// The caller holds the read lock.
func (s *Set) candidates(model []string) []candidate {
	if len(model) == 0 {
		return nil
	}
	seen := map[ref]bool{}
	var out []candidate
	for _, t := range model {
		for _, r := range s.postings[t] {
			if seen[r] {
				continue
			}
			seen[r] = true
			out = append(out, candidate{adv: r.adv, rec: r.adv.Records[r.rec]})
		}
	}
	return out
}

// Counts is the set's own summary.
func (s *Set) Counts() Counts {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := Counts{Documents: len(s.advisories), Records: s.records,
		Skipped: s.skipped, Loaded: s.loaded,
		Sources:     append([]SourceStatus(nil), s.sources...),
		Assessments: s.Assessments.Load(), Affected: s.Affected.Load()}
	return c
}

// Advisories is every document the set holds, newest first. It is the answer to
// "what does this proxy actually know about", which is the first question an
// operator asks of a directory somebody else fills.
func (s *Set) Advisories() []*Advisory {
	s.mu.RLock()
	out := append([]*Advisory(nil), s.advisories...)
	s.mu.RUnlock()
	sort.SliceStable(out, func(i, j int) bool { return out[i].Released.After(out[j].Released) })
	return out
}

// Documents is how many advisories are loaded.
func (s *Set) Documents() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.advisories)
}
