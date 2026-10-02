package tacacs

import (
	"errors"
	"net"

	"github.com/rom/xproxy/internal/safe"
)

// guard is the panic guard every goroutine this kind starts carries.
func guard() { safe.Guard("tacacs session") }

// errorsAsTimeout is errors.As against net.Error plus the timeout test, in
// one place because the accept loop and both relay loops ask the same
// question.
func errorsAsTimeout(err error, ne *net.Error) bool {
	return errors.As(err, ne) && (*ne).Timeout()
}
