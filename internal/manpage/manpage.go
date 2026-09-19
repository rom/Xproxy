// Package manpage renders the Markdown documentation of this repository
// as troff manual pages (man macros plus tbl tables). It covers the
// subset the docs use: ATX headings, paragraphs, fenced code blocks,
// pipe tables, bullet lists and inline code, bold and emphasis.
package manpage

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Page describes one manual page.
type Page struct {
	Name    string // xproxy, xproxyctl, xproxy.yaml
	Section int    // 5 or 8
	Source  string // footer left, for example "Xproxy 1.3"
	Manual  string // header centre, for example "System administration"
	// Markdown is the source; its level 1 heading is dropped (the
	// title line carries the name), level 2 headings become sections
	// and level 3 headings subsections.
	Markdown []byte
}

// Render returns the troff document.
func Render(p Page) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, ".\\\" Generated from Markdown by internal/manpage; do not edit.\n")
	fmt.Fprintf(&b, ".TH %s %d \"\" \"%s\" \"%s\"\n", strings.ToUpper(escape(p.Name)), p.Section, escape(p.Source), escape(p.Manual))
	b.WriteString(".nh\n.ad l\n")
	r := &renderer{out: &b}
	r.render(p.Markdown)
	return b.Bytes()
}

type renderer struct {
	out  *bytes.Buffer
	para []string
	list bool
}

func (r *renderer) render(md []byte) {
	sc := bufio.NewScanner(bytes.NewReader(md))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		switch {
		case strings.HasPrefix(line, "```"):
			r.flush()
			var code []string
			for i++; i < len(lines) && !strings.HasPrefix(lines[i], "```"); i++ {
				code = append(code, lines[i])
			}
			r.endList()
			r.code(code)
		case strings.HasPrefix(line, "# "):
			r.flush()
		case strings.HasPrefix(line, "## "):
			r.flush()
			r.endList()
			fmt.Fprintf(r.out, ".SH %s\n", quoteHeading(strings.TrimPrefix(line, "## ")))
		case strings.HasPrefix(line, "### "):
			r.flush()
			r.endList()
			fmt.Fprintf(r.out, ".SS %s\n", quoteHeading(strings.TrimPrefix(line, "### ")))
		case strings.HasPrefix(line, "#### "):
			r.flush()
			r.endList()
			fmt.Fprintf(r.out, ".SS %s\n", quoteHeading(strings.TrimPrefix(line, "#### ")))
		case strings.HasPrefix(line, "|"):
			r.flush()
			var rows []string
			for ; i < len(lines) && strings.HasPrefix(lines[i], "|"); i++ {
				rows = append(rows, lines[i])
			}
			i--
			r.endList()
			r.table(rows)
		case strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* "):
			r.flush()
			// A hanging indent from plain requests rather than .IP: with
			// groff 1.23 an .IP paragraph leaves every later tbl text
			// block unable to adjust its lines.
			if !r.list {
				r.list = true
				r.out.WriteString(".RS 3n\n")
			}
			r.out.WriteString(".PP\n.ti -3n\n\\(bu\n")
			item := strings.TrimSpace(line[2:])
			// Continuation lines of the item are indented.
			for i+1 < len(lines) && strings.HasPrefix(lines[i+1], "  ") && strings.TrimSpace(lines[i+1]) != "" && !strings.HasPrefix(strings.TrimSpace(lines[i+1]), "- ") {
				i++
				item += " " + strings.TrimSpace(lines[i])
			}
			r.out.WriteString(guardStart(inline(item)) + "\n")
		case strings.TrimSpace(line) == "":
			r.flush()
		default:
			if r.list && !strings.HasPrefix(line, "  ") {
				r.endList()
			}
			r.para = append(r.para, strings.TrimSpace(line))
		}
	}
	r.flush()
	r.endList()
}

func (r *renderer) flush() {
	if len(r.para) == 0 {
		return
	}
	r.out.WriteString(".PP\n")
	r.out.WriteString(guardStart(inline(strings.Join(r.para, " "))) + "\n")
	r.para = nil
}

func (r *renderer) endList() {
	if r.list {
		r.out.WriteString(".RE\n.PP\n")
		r.list = false
	}
}

func (r *renderer) code(lines []string) {
	r.out.WriteString(".PP\n.RS 4\n.nf\n.ft CR\n")
	for _, l := range lines {
		r.out.WriteString(escapeCode(l) + "\n")
	}
	r.out.WriteString(".ft\n.fi\n.RE\n")
}

// table renders a pipe table with tbl: header row bold, the last column
// expanded and every cell a text block so long descriptions wrap.
func (r *renderer) table(rows []string) {
	cells := make([][]string, 0, len(rows))
	for i, row := range rows {
		if i == 1 && strings.Trim(row, "|-: ") == "" {
			continue // separator
		}
		cells = append(cells, splitRow(row))
	}
	if len(cells) == 0 {
		return
	}
	cols := 0
	for _, c := range cells {
		cols = max(cols, len(c))
	}
	// Cells are separated by a tab, tbl's default, so a pipe inside a
	// cell (escaped in the source) needs no escaping here.
	r.out.WriteString(".PP\n.TS\nallbox;\n")
	// Explicit widths for the leading columns, from their longest
	// unbreakable token (tbl otherwise gives every text block a fifth of
	// the line and a long entry cannot break); the last column takes the
	// rest.
	rendered := make([][]string, len(cells))
	for r, row := range cells {
		rendered[r] = make([]string, cols)
		for i := range rendered[r] {
			if i < len(row) {
				rendered[r][i] = guardStart(inlineWith(row[i], true))
			}
		}
	}
	spec := make([]string, cols)
	head := make([]string, cols)
	for i := 0; i < cols-1; i++ {
		w := columnWidth(rendered, i)
		spec[i] = "lw(" + w + ")"
		head[i] = "lbw(" + w + ")"
	}
	spec[cols-1] = "lx"
	head[cols-1] = "lbx"
	r.out.WriteString(strings.Join(head, " ") + "\n" + strings.Join(spec, " ") + ".\n")
	for _, row := range rendered {
		parts := make([]string, cols)
		for i, cell := range row {
			parts[i] = "T{\n" + cell + "\nT}"
		}
		r.out.WriteString(strings.Join(parts, "\t") + "\n")
	}
	r.out.WriteString(".TE\n")
}

// columnWidth returns the width of column i in inches: its longest
// unbreakable token at ten characters per inch (the terminal density
// man pages are read at), between 0.6i and 2.4i.
func columnWidth(rows [][]string, i int) string {
	longest := 5
	for _, row := range rows {
		for _, tok := range strings.FieldsFunc(row[i], func(r rune) bool { return r == ' ' }) {
			for _, piece := range strings.Split(tok, `\:`) {
				longest = max(longest, visibleLen(piece))
			}
		}
	}
	tenths := min(max(longest+1, 6), 24)
	return fmt.Sprintf("%d.%di", tenths/10, tenths%10)
}

// visibleLen counts the characters troff prints for an escaped token.
func visibleLen(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			n++
			continue
		}
		if i+1 >= len(s) {
			break
		}
		switch s[i+1] {
		case 'f': // \fB, \fR, \fI
			i += 2
		case '(': // \(aq, \(bu, \(dq
			i += 3
			n++
		case '&': // \&
			i++
		default: // \-, \e, \:
			i++
			n++
		}
	}
	return n
}

// splitRow splits a pipe table row into cells; a pipe inside a code span
// or escaped as \| belongs to the cell.
func splitRow(row string) []string {
	row = strings.TrimSpace(row)
	row = strings.TrimPrefix(row, "|")
	row = strings.TrimSuffix(row, "|")
	var cells []string
	var cur strings.Builder
	inCode := false
	for i := 0; i < len(row); i++ {
		switch {
		case row[i] == '`':
			inCode = !inCode
			cur.WriteByte(row[i])
		case row[i] == '\\' && i+1 < len(row) && row[i+1] == '|':
			cur.WriteByte('|')
			i++
		case row[i] == '|' && !inCode:
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(row[i])
		}
	}
	cells = append(cells, strings.TrimSpace(cur.String()))
	return cells
}

func quoteHeading(h string) string {
	return `"` + strings.ReplaceAll(inline(h), `"`, `\(dq`) + `"`
}

// inline converts inline Markdown to troff: `code` and **bold** to bold,
// *emphasis* and _emphasis_ to italics, links to their text, and escapes
// the rest.
func inline(s string) string { return inlineWith(s, false) }

// inlineWith renders inline Markdown; with breakable, code spans get
// break points after punctuation so that long keys and paths wrap inside
// table cells instead of widening the table.
func inlineWith(s string, breakable bool) string {
	var out strings.Builder
	code := func(c string) string {
		if breakable {
			return breakPoints(escape(c))
		}
		return escape(c)
	}
	for i := 0; i < len(s); {
		switch {
		case s[i] == '`':
			end := strings.IndexByte(s[i+1:], '`')
			if end < 0 {
				out.WriteString(escape(s[i:]))
				return out.String()
			}
			out.WriteString(`\fB` + code(s[i+1:i+1+end]) + `\fR`)
			i += end + 2
		case strings.HasPrefix(s[i:], "**"):
			end := strings.Index(s[i+2:], "**")
			if end < 0 {
				out.WriteString(escape(s[i:]))
				return out.String()
			}
			out.WriteString(`\fB` + inlineWith(s[i+2:i+2+end], breakable) + `\fR`)
			i += end + 4
		case s[i] == '[':
			close := strings.IndexByte(s[i:], ']')
			if close > 0 && i+close+1 < len(s) && s[i+close+1] == '(' {
				if paren := strings.IndexByte(s[i+close:], ')'); paren > 0 {
					out.WriteString(inlineWith(s[i+1:i+close], breakable))
					i += close + paren + 1
					continue
				}
			}
			out.WriteString(escape(s[i : i+1]))
			i++
		case (s[i] == '*' || s[i] == '_') && i+1 < len(s) && s[i+1] != ' ' && (i == 0 || s[i-1] == ' ' || s[i-1] == '('):
			end := strings.IndexByte(s[i+1:], s[i])
			if end <= 0 {
				out.WriteString(escape(s[i : i+1]))
				i++
				continue
			}
			out.WriteString(`\fI` + escape(s[i+1:i+1+end]) + `\fR`)
			i += end + 2
		default:
			word := s[i:]
			if sp := strings.IndexByte(word, ' '); sp >= 0 {
				word = word[:sp]
			}
			if breakable && (strings.Contains(word, "://") || len(word) > 20) && !strings.ContainsAny(word, "`*[]") {
				out.WriteString(breakPoints(escape(word)))
				i += len(word)
				continue
			}
			_, size := utf8.DecodeRuneInString(s[i:])
			out.WriteString(escape(s[i : i+size]))
			if breakable && size == 1 && strings.IndexByte("|/,;", s[i]) >= 0 {
				out.WriteString(`\:`)
			}
			i += size
		}
	}
	return out.String()
}

// breakPoints inserts troff's invisible break point after the
// punctuation of an already escaped token.
func breakPoints(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		out.WriteByte(s[i])
		if i == len(s)-1 {
			break
		}
		switch s[i] {
		case '.', '_', '/', ',', ':', '=':
			out.WriteString(`\:`)
		case '-':
			if i > 0 && s[i-1] == '\\' { // an escaped hyphen
				out.WriteString(`\:`)
			}
		}
	}
	return out.String()
}

// escape protects troff specials in running text.
func escape(s string) string {
	var out strings.Builder
	for _, ch := range s {
		switch ch {
		case '\\':
			out.WriteString(`\e`)
		case '-':
			out.WriteString(`\-`)
		case '\'':
			out.WriteString(`\(aq`)
		default:
			if ch > 127 {
				// groff reads the page as Latin-1 unless told otherwise;
				// a named Unicode glyph renders everywhere.
				fmt.Fprintf(&out, `\[u%04X]`, ch)
				continue
			}
			out.WriteRune(ch)
		}
	}
	return out.String()
}

// guardStart protects an output line that starts with a troff control
// character (a dot or an apostrophe would be read as a request).
func guardStart(line string) string {
	if strings.HasPrefix(line, ".") || strings.HasPrefix(line, "'") {
		return `\&` + line
	}
	return line
}

// escapeCode protects a line of a code block: backslashes, leading
// control characters and hyphens (kept as ASCII minus).
func escapeCode(s string) string {
	s = strings.ReplaceAll(s, `\`, `\e`)
	s = strings.ReplaceAll(s, "-", `\-`)
	var out strings.Builder
	for _, ch := range s {
		if ch > 127 {
			fmt.Fprintf(&out, `\[u%04X]`, ch)
			continue
		}
		out.WriteRune(ch)
	}
	s = out.String()
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "'") {
		s = `\&` + s
	}
	return s
}
