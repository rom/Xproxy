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
	name = strings.ToLower(strings.TrimSuffix(name, "."))
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
