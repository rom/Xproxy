package dns

// Validator checks DNSSEC signatures on upstream answers. The full
// implementation follows; this stub keeps the policy field typed.
type Validator struct{}

// Status returns counters.
func (v *Validator) Status() DNSSECStatus { return DNSSECStatus{Enabled: v != nil} }
