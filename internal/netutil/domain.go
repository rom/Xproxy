package netutil

import "strings"

// PublicSuffixes lists the common two-label suffixes under which anyone
// can register a name. It is a safety net, not the public suffix list:
// it exists so that "co.uk" is not mistaken for somebody's domain, and
// it is deliberately short, because a list that tries to be complete and
// is not is worse than one that says what it covers.
//
// Two very different judgements read it. A wildcard origin like
// "https://*.co.uk" is refused because the suffix is a registry and the
// wildcard would cover the whole of it. And DNS tunnel detection groups
// a client's queries by the name somebody actually registered, so that
// a thousand subdomains under one tunnel domain are counted together
// rather than as a thousand unrelated names.
var PublicSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true, "ltd.uk": true, "plc.uk": true, "net.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true, "id.au": true,
	"co.nz": true, "net.nz": true, "org.nz": true, "co.za": true, "org.za": true, "web.za": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true, "go.jp": true, "co.kr": true, "or.kr": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "com.hk": true, "com.tw": true, "com.sg": true, "com.my": true,
	"co.in": true, "net.in": true, "org.in": true, "co.id": true, "com.ph": true, "com.vn": true, "co.th": true,
	"com.br": true, "net.br": true, "org.br": true, "com.mx": true, "com.ar": true, "com.co": true, "com.pe": true,
	"com.tr": true, "com.ua": true, "com.pl": true, "com.ru": true, "co.il": true, "com.eg": true, "com.sa": true,
	"com.ng": true, "co.ke": true, "com.gh": true, "co.tz": true, "com.pk": true, "com.bd": true,
	"github.io": true, "gitlab.io": true, "herokuapp.com": true, "azurewebsites.net": true, "cloudfront.net": true,
	"appspot.com": true, "web.app": true, "firebaseapp.com": true, "vercel.app": true, "netlify.app": true, "pages.dev": true,
	"workers.dev": true, "amazonaws.com": true, "blogspot.com": true, "wordpress.com": true,
}

// ASCIILower folds a DNS name the way DNS folds one: A-Z to a-z, and
// nothing else.
//
// strings.ToLower is wrong for this twice over. It applies Unicode
// case rules, which map characters DNS treats as distinct onto one
// another -- the Kelvin sign folds to "k" -- so two different names
// compare equal. And on bytes that are not valid UTF-8, which a DNS
// label may perfectly well contain, it produces the replacement
// character: every such byte becomes the same three bytes, so distinct
// names fold to one string, and the name gets longer than it was.
//
// Wherever a folded name is a key, a cache entry or the input to a
// hash, that collision is the bug. RFC 4343 is explicit that DNS case
// insensitivity is ASCII only.
func ASCIILower(s string) string {
	hasUpper := false
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// ASCIIEqualFold compares two DNS labels the way DNS compares them.
// strings.EqualFold folds by Unicode rules and would call two distinct
// labels the same.
func ASCIIEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// Registrable returns the name somebody registered: the last two labels,
// or three where the last two are a registry suffix. A name with fewer
// labels than that is returned as it is, because there is nothing under
// it to group.
//
// The trailing dot and the case are dropped, so the answer is a stable
// key. Where the suffix list does not know a registry the answer is the
// last two labels, which groups a little too coarsely rather than not at
// all — the direction that keeps a detector looking.
func Registrable(name string) string {
	name = ASCIILower(strings.TrimSuffix(name, "."))
	if name == "" {
		return ""
	}
	labels := strings.Split(name, ".")
	if len(labels) <= 2 {
		return name
	}
	last2 := labels[len(labels)-2] + "." + labels[len(labels)-1]
	if PublicSuffixes[last2] && len(labels) >= 3 {
		return labels[len(labels)-3] + "." + last2
	}
	return last2
}
