package tui

import (
	"os"
	"testing"
)

func osPipe(t *testing.T) (*os.File, *os.File, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	return r, w, nil
}
