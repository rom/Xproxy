package replay

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Turning a decoded session into something to look at: PNG frames, one
// self-contained HTML page that plays them, and a timeline of what the
// stream did.
//
// The page is deliberately a file rather than a server: a recording is
// evidence, and a reviewer should be able to keep the page beside it, on
// a machine with no network, and have it still play.

// Frame is one moment of a session.
type Frame struct {
	At   time.Duration
	PNG  []byte
	Note string
}

// MaxFrames bounds how many frames a replay produces. A long session
// sends thousands of updates; a page holding all of them is a page
// nothing can open.
const MaxFrames = 2000

// FrameSet collects frames under a bound, sampling when there are more
// updates than frames asked for.
type FrameSet struct {
	Frames []Frame
	// Max is the most frames to keep. Zero means MaxFrames.
	Max int
	// Every keeps one frame in this many updates. Zero means every one,
	// until Max is reached.
	Every int
	seen  int
}

// Add encodes the framebuffer as it is now, subject to the bounds.
func (fs *FrameSet) Add(at time.Duration, fb *Framebuffer, note string) error {
	fs.seen++
	if fs.Every > 1 && fs.seen%fs.Every != 0 {
		return nil
	}
	max := fs.Max
	if max <= 0 {
		max = MaxFrames
	}
	if len(fs.Frames) >= max {
		return nil
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, fb.Image()); err != nil {
		return err
	}
	fs.Frames = append(fs.Frames, Frame{At: at, PNG: buf.Bytes(), Note: note})
	return nil
}

// WritePNGs writes one file per frame into a directory that must exist.
func (fs *FrameSet) WritePNGs(dir string) ([]string, error) {
	out := make([]string, 0, len(fs.Frames))
	for i, f := range fs.Frames {
		name := filepath.Join(dir, fmt.Sprintf("frame-%05d.png", i+1))
		if err := os.WriteFile(name, f.PNG, 0o600); err != nil {
			return out, err
		}
		out = append(out, name)
	}
	return out, nil
}

// WritePage writes a self-contained player: the frames as data URIs, the
// recorded timing, and the marks beside them.
func (fs *FrameSet) WritePage(w io.Writer, title string, notes []string) error {
	var b bytes.Buffer
	b.WriteString("<!doctype html>\n<meta charset=\"utf-8\">\n")
	fmt.Fprintf(&b, "<title>%s</title>\n", html.EscapeString(title))
	b.WriteString(`<style>
:root{color-scheme:light dark}
body{margin:0;font:14px/1.5 system-ui,sans-serif;background:#111;color:#eee}
header{padding:8px 12px;background:#000;font-weight:600}
#screen{display:block;max-width:100%;image-rendering:pixelated;background:#000;margin:0 auto}
#bar{display:flex;gap:8px;align-items:center;padding:8px 12px;background:#000;position:sticky;top:0}
#notes{padding:8px 12px;white-space:pre-wrap;font-family:ui-monospace,monospace;font-size:12px;color:#bbb}
button,input{font:inherit}
</style>
`)
	fmt.Fprintf(&b, "<header>%s</header>\n", html.EscapeString(title))
	b.WriteString(`<div id="bar">
<button id="play">Play</button>
<input id="seek" type="range" min="0" value="0" step="1" style="flex:1">
<span id="clock">0.000s</span>
</div>
<img id="screen" alt="recorded screen">
<div id="notes"></div>
<script>
const frames = FRAMES;
const notes = NOTES;
const img = document.getElementById('screen');
const seek = document.getElementById('seek');
const clock = document.getElementById('clock');
const play = document.getElementById('play');
seek.max = Math.max(0, frames.length - 1);
let i = 0, timer = null;
function show(n){
  i = Math.max(0, Math.min(frames.length - 1, n));
  if (!frames.length) return;
  img.src = 'data:image/png;base64,' + frames[i].d;
  seek.value = i;
  clock.textContent = (frames[i].t / 1000).toFixed(3) + 's';
}
function stop(){ if (timer) { clearTimeout(timer); timer = null; } play.textContent = 'Play'; }
function step(){
  if (i >= frames.length - 1) { stop(); return; }
  const wait = Math.min(2000, Math.max(16, frames[i+1].t - frames[i].t));
  timer = setTimeout(() => { show(i + 1); step(); }, wait);
}
play.onclick = () => { if (timer) { stop(); } else { play.textContent = 'Pause'; step(); } };
seek.oninput = () => { stop(); show(Number(seek.value)); };
document.getElementById('notes').textContent = notes.join('\n');
show(0);
</script>
`)
	page := b.String()
	var frames bytes.Buffer
	frames.WriteByte('[')
	for i, f := range fs.Frames {
		if i > 0 {
			frames.WriteByte(',')
		}
		fmt.Fprintf(&frames, `{"t":%d,"d":"%s"}`, f.At.Milliseconds(), base64.StdEncoding.EncodeToString(f.PNG))
	}
	frames.WriteByte(']')
	var ns bytes.Buffer
	ns.WriteByte('[')
	for i, n := range notes {
		if i > 0 {
			ns.WriteByte(',')
		}
		fmt.Fprintf(&ns, "%q", n)
	}
	ns.WriteByte(']')
	page = replaceOnce(page, "FRAMES", frames.String())
	page = replaceOnce(page, "NOTES", ns.String())
	_, err := io.WriteString(w, page)
	return err
}

// replaceOnce is a spelling of strings.Replace with a count of one that
// says so at the call site.
func replaceOnce(s, from, to string) string {
	i := indexOf(s, from)
	if i < 0 {
		return s
	}
	return s[:i] + to + s[i+len(from):]
}

func indexOf(s, sub string) int {
	return bytes.Index([]byte(s), []byte(sub))
}
