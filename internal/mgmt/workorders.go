package mgmt

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/access"
)

// Work orders over the control plane: filing the change reference somebody
// already has, and closing it when the work is done.
//
// Three calls and no approval step, which is the difference from the grants
// next door. Filing a work order permits nothing, so there is nobody to ask;
// what it does is put the reference in the hash-chained trail and change the
// tone of the engineering events on that device while it is open. The calls
// are audited all the same, because "who said this download was expected" is
// exactly the question somebody will be asking.

// WorkOrderReport is what GET /v1/workorders answers.
type WorkOrderReport struct {
	// Open is how many are in force now, which is the number a dashboard
	// wants; Orders is all of them, most recently filed first.
	Open   int                    `json:"open"`
	Orders []access.WorkOrderView `json:"work_orders"`
}

// workOrderRequest is the body of POST /v1/workorders.
type workOrderRequest struct {
	// Reference is the maintenance system's own identifier, Device what the
	// work is on. Both are required: a work order with no reference is not a
	// work order, and one with no device covers nothing.
	Reference string `json:"reference"`
	Device    string `json:"device"`
	// Listener narrows it to one listener; empty is every listener that
	// reaches the device.
	Listener string `json:"listener,omitempty"`
	// Note is what the work is, By who is filing it.
	Note string `json:"note,omitempty"`
	By   string `json:"by"`
	// Duration is how long the work lasts (a Go duration), and Start an
	// optional RFC 3339 time for work that begins later -- a shutdown next
	// weekend, filed now.
	Duration string `json:"duration"`
	Start    string `json:"start,omitempty"`
}

// workOrderClose is the body of DELETE /v1/workorders.
type workOrderClose struct {
	Reference string `json:"reference"`
	By        string `json:"by"`
	Note      string `json:"note,omitempty"`
}

// listWorkOrders answers GET /v1/workorders.
func (s *Server) listWorkOrders(w http.ResponseWriter, r *http.Request) {
	l := s.ledger(w)
	if l == nil {
		return
	}
	orders := l.WorkOrders()
	if state := strings.TrimSpace(r.URL.Query().Get("state")); state != "" {
		kept := orders[:0]
		for _, o := range orders {
			if strings.EqualFold(o.State, state) {
				kept = append(kept, o)
			}
		}
		orders = kept
	}
	if device := strings.TrimSpace(r.URL.Query().Get("device")); device != "" {
		kept := orders[:0]
		for _, o := range orders {
			if o.Device == device {
				kept = append(kept, o)
			}
		}
		orders = kept
	}
	if orders == nil {
		orders = []access.WorkOrderView{}
	}
	writeJSON(w, 200, WorkOrderReport{Open: l.OpenWorkOrders(), Orders: orders})
}

// fileWorkOrder answers POST /v1/workorders.
func (s *Server) fileWorkOrder(w http.ResponseWriter, r *http.Request) {
	l := s.ledger(w)
	if l == nil {
		return
	}
	var body workOrderRequest
	if !decodeAccess(w, r, &body) {
		return
	}
	d, err := time.ParseDuration(strings.TrimSpace(body.Duration))
	if err != nil {
		writeJSON(w, 400, result{Error: "duration: " + err.Error()})
		return
	}
	start := time.Now()
	if body.Start != "" {
		if start, err = time.Parse(time.RFC3339, strings.TrimSpace(body.Start)); err != nil {
			writeJSON(w, 400, result{Error: "start: " + err.Error()})
			return
		}
	}
	v, err := l.FileWorkOrder(access.WorkOrder{
		Reference: body.Reference, Device: body.Device, Listener: body.Listener,
		Note: body.Note, By: body.By, NotBefore: start, Expires: start.Add(d),
	})
	if err != nil {
		writeJSON(w, workOrderStatus(err), result{Error: err.Error()})
		return
	}
	s.audit(r, "work_order_filed", "reference", v.Reference, "device", v.Device,
		"listener", v.Listener, "by", v.By, "note", v.Note,
		"not_before", v.NotBefore.UTC().Format(time.RFC3339),
		"expires", v.Expires.UTC().Format(time.RFC3339))
	writeJSON(w, 200, v)
}

// closeWorkOrder answers DELETE /v1/workorders. The reference may come in the
// body or the query, because closing one from a script and closing one from a
// link are both things people do.
func (s *Server) closeWorkOrder(w http.ResponseWriter, r *http.Request) {
	l := s.ledger(w)
	if l == nil {
		return
	}
	var body workOrderClose
	if r.ContentLength != 0 {
		if !decodeAccess(w, r, &body) {
			return
		}
	}
	q := r.URL.Query()
	if body.Reference == "" {
		body.Reference = q.Get("reference")
	}
	if body.By == "" {
		body.By = q.Get("by")
	}
	if body.Note == "" {
		body.Note = q.Get("note")
	}
	v, err := l.CloseWorkOrder(body.Reference, body.By, body.Note)
	if err != nil {
		writeJSON(w, workOrderStatus(err), result{Error: err.Error()})
		return
	}
	s.audit(r, "work_order_closed", "reference", v.Reference, "device", v.Device,
		"by", body.By, "note", body.Note)
	writeJSON(w, 200, v)
}

// workOrderStatus maps a ledger error to a status.
func workOrderStatus(err error) int {
	switch {
	case errors.Is(err, access.ErrTooManyWorkOrders):
		return 429
	case strings.HasPrefix(err.Error(), "no work order"):
		return 404
	case strings.Contains(err.Error(), "already closed"):
		return 409
	}
	return 400
}

// workOrderRoutes registers the three calls.
func (s *Server) workOrderRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/workorders", s.listWorkOrders)
	mux.HandleFunc("POST /v1/workorders", s.fileWorkOrder)
	mux.HandleFunc("DELETE /v1/workorders", s.closeWorkOrder)
}
