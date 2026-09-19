package manpage

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite docs/man from the Markdown sources")

func TestRender(t *testing.T) {
	md := "# t\n\n## NAME\n\nt - a test\n\n## DETAILS\n\nA `code` word, **bold** and *em* with a -dash.\n.starts with a dot\n\n- first item\n  continued\n- second `x`\n\n```\n.nf line\nback\\slash -x\n```\n\n| Key | Type | Description |\n|-----|------|-------------|\n| `a` | int | one \\| two |\n| `tls.cert_file` | path | see https://x.test/a |\n| `a|b` | `x` | pipe in code |\n\n### Sub\n\n[link text](http://x) end.\n"
	out := string(Render(Page{Name: "t", Section: 8, Source: "S", Manual: "M", Markdown: []byte(md)}))
	for _, want := range []string{
		".TH T 8 \"\" \"S\" \"M\"\n",
		".SH \"NAME\"\n.PP\nt \\- a test\n",
		".SH \"DETAILS\"\n.PP\nA \\fBcode\\fR word, \\fBbold\\fR and \\fIem\\fR with a \\-dash. .starts with a dot\n",
		".RS 3n\n.PP\n.ti -3n\n\\(bu\nfirst item continued\n.PP\n.ti -3n\n\\(bu\nsecond \\fBx\\fR\n.RE\n.PP\n",
		".nf\n.ft CR\n\\&.nf line\nback\\eslash \\-x\n.ft\n.fi\n",
		".TS\nallbox;\nlbw(0.6i) lbw(0.6i) lbx\nlw(0.6i) lw(0.6i) lx.\nT{\nKey\nT}\tT{\nType\nT}\tT{\nDescription\nT}\nT{\n\\fBa\\fR\nT}\tT{\nint\nT}\tT{\none |\\: two\nT}\nT{\n\\fBtls.\\:cert_\\:file\\fR\nT}\tT{\npath\nT}\tT{\nsee https:\\:/\\:/\\:x.\\:test/\\:a\nT}\nT{\n\\fBa|b\\fR\nT}\tT{\n\\fBx\\fR\nT}\tT{\npipe in code\nT}\n.TE\n",
		".SS \"Sub\"\n.PP\nlink text end.\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// TestPagesCurrent fails when docs/man is stale relative to the Markdown
// sources; regenerate with go generate ./internal/manpage.
func TestPagesCurrent(t *testing.T) {
	pages, err := Build("../../docs")
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 3 {
		t.Fatalf("pages: %v", pages)
	}
	for name, want := range pages {
		path := filepath.Join("../../docs/man", name)
		if *update {
			if err := os.WriteFile(path, want, 0o644); err != nil { //nolint:gosec // documentation
				t.Fatal(err)
			}
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale: run go generate ./internal/manpage", name)
		}
		if !bytes.Contains(want, []byte(".SH \"NAME\"")) || !bytes.Contains(want, []byte(".SH \"SEE ALSO\"")) {
			t.Errorf("%s: NAME or SEE ALSO section missing", name)
		}
	}
	// Every xproxyctl command is documented.
	ctl := strings.NewReplacer(`\:`, "", `\-`, "-").Replace(string(pages["xproxyctl.8"]))
	for _, cmd := range []string{"status", "reload", "rotate-secret", "tls", "completion", "schema", "help", "tui"} {
		if !strings.Contains(ctl, "\\fB"+cmd+"\\fR") {
			t.Errorf("xproxyctl.8: command %s missing", cmd)
		}
	}
	// groff, when installed, must format every page without a warning.
	groff, err := exec.LookPath("groff")
	if err != nil {
		t.Skip("groff not installed")
	}
	for name, content := range pages {
		cmd := exec.Command(groff, "-t", "-man", "-Tutf8", "-z", "-ww")
		cmd.Stdin = bytes.NewReader(content)
		if out, err := cmd.CombinedOutput(); err != nil || len(out) > 0 {
			t.Errorf("%s: groff: %v\n%s", name, err, out)
		}
	}
}
