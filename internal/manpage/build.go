package manpage

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// Source is the footer of every page.
const Source = "Xproxy"

// Build renders the manual pages of the repository from the Markdown
// under docsDir: the daemon and tool pages from docs/man/*.8.md and
// xproxy.yaml.5 from docs/CONFIG.md. The result maps the file name to
// its troff content.
func Build(docsDir string) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, p := range []struct {
		name   string
		src    string
		manual string
	}{
		{"xproxy", "man/xproxy.8.md", "System administration"},
		{"xgate", "man/xgate.8.md", "System administration"},
		{"xrelay", "man/xrelay.8.md", "System administration"},
		{"xot", "man/xot.8.md", "System administration"},
		{"xproxyctl", "man/xproxyctl.8.md", "System administration"},
		{"xproxy-fleet", "man/xproxy-fleet.8.md", "System administration"},
		{"xproxy-replay", "man/xproxy-replay.8.md", "System administration"},
		{"xproxy-simulate", "man/xproxy-simulate.8.md", "System administration"},
		{"xsigner", "man/xsigner.8.md", "System administration"},
	} {
		md, err := os.ReadFile(filepath.Join(docsDir, p.src)) //nolint:gosec // documentation paths from the generator
		if err != nil {
			return nil, err
		}
		out[p.name+".8"] = Render(Page{Name: p.name, Section: 8, Source: Source, Manual: p.manual, Markdown: md})
	}
	cfg, err := os.ReadFile(filepath.Join(docsDir, "CONFIG.md")) //nolint:gosec // documentation path from the generator
	if err != nil {
		return nil, err
	}
	out["xproxy.yaml.5"] = Render(Page{Name: "xproxy.yaml", Section: 5, Source: Source, Manual: "File formats", Markdown: configPage(cfg)})
	return out, nil
}

// configPage wraps the configuration reference in the sections a file
// format page has: the reference's own introduction becomes DESCRIPTION
// and its sections follow.
func configPage(cfg []byte) []byte {
	var b bytes.Buffer
	b.WriteString("# xproxy.yaml\n\n## NAME\n\nxproxy.yaml - configuration of xproxy\n\n")
	b.WriteString("## SYNOPSIS\n\n`/etc/xproxy/xproxy.yaml`\n\n## DESCRIPTION\n\n")
	// Drop the reference's level 1 heading; the rest follows as is.
	if i := bytes.IndexByte(cfg, '\n'); i >= 0 && bytes.HasPrefix(cfg, []byte("# ")) {
		cfg = cfg[i+1:]
	}
	b.Write(cfg)
	fmt.Fprintf(&b, "\n\n## SEE ALSO\n\n`xproxy`(8), `xproxyctl`(8). The same reference is `docs/CONFIG.md`; a JSON schema for editors is installed at `/usr/share/xproxy/xproxy.schema.json` and printed by `xproxyctl schema`.\n")
	return b.Bytes()
}
