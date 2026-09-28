package mms

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: mms listener is a relay in front of IEC 61850 substation IEDs, on TCP 102.
//
// It is the deepest protocol stack in this project -- TPKT, COTP, ISO session, ISO
// presentation, ACSE, MMS -- and the one whose *names* carry the most. Everywhere
// else in this tree the relay has to be told what a register or a point means. Here
// the object name says it: `XCBR1$CO$Pos$Oper` operates a circuit breaker,
// `PTOC1$SG$StrVal$setMag$f` changes a protection relay's trip characteristic, and
// `LLN0$BR$brcbST$RptEna` decides whether the control centre hears about either. So
// a useful policy can be written for an estate whose SCL files nobody has read,
// which is most of them.
//
// The listener takes **no TLS section**. MMS on TCP 102 has none: IEC 62351-4 adds
// TLS beneath the session layer, and a listener that terminated it would be
// terminating the only end-to-end protection this protocol has. A deployment that
// wants TLS in front of the relay puts a tcp listener with a tls section there.
//
// Two things this relay does that the devices may not.
//
// It **sees the password**. IEC 61850-8-1's ACSE authentication value is a
// cleartext GraphicString, and on most of the installed base it is the only
// authentication an IED has. This relay counts every association that carries one and
// raises a finding for it, records its length and never its value, and can refuse it
// where the estate has moved to 62351-4. That is the whole of what an honest relay can
// do about it: the alternative -- holding the password to check it -- would make this
// the most valuable thing on the substation network.
//
// And it can **require select before operate**. IEC 61850 leaves that to each
// object's `ctlModel`, `ctlModel` lives in `$CF$`, and `$CF$` is writable -- so a
// client with configuration access can turn the interlock off and then operate
// directly. A listener that tracks the selection itself, and records it on the IED's
// *positive* answer rather than on the client's asking, has put the interlock
// somewhere the configuration cannot reach.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "mms",
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.MMS == nil {
				return nil, fmt.Errorf("listener %s: the mms section is required", su.Config.Name)
			}
			return newServer(su.Host, su.Config, su.Net)
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
