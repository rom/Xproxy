package bacnet

import "sort"

// lower folds ASCII only. A service name is ASCII in every edition of the
// standard, and Unicode case folding would make two different names equal
// in some locale -- which for a name that decides whether a write reaches
// a controller is not a trade worth making.
func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func sortStrings(s []string) { sort.Strings(s) }
