package ssh

import (
	"testing"

	sftpwire "github.com/rom/xproxy/internal/sftp"
)

func TestSFTPFailedOpenReleasesPendingSlot(t *testing.T) {
	files := newSFTPFiles(1)
	files.expect(1, "/missing", true)
	files.forget(1)
	files.expect(2, "/upload", true)
	files.bind(2, "handle", nil)

	file := files.file("handle")
	if file == nil || file.path != "/upload" || file.held == nil {
		t.Fatal("a failed open prevented the next scanned open from being tracked")
	}
}

func TestSFTPICAPRefusesUnknownHandle(t *testing.T) {
	files := newSFTPFiles(1)
	req := sftpwire.Request{Type: sftpwire.WRITE, Handle: "untracked"}

	if got := (&session{}).sftpWrite(&sftpPolicy{}, files, req, true); got != "unknown_handle" {
		t.Fatalf("ICAP write on an untracked handle refused as %q, want unknown_handle", got)
	}
}
