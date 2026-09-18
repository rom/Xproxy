package dns

// DNSSECStatus is the management view of the validator.
type DNSSECStatus struct {
	Enabled       bool   `json:"enabled"`
	Secure        uint64 `json:"secure"`
	Insecure      uint64 `json:"insecure"`
	Bogus         uint64 `json:"bogus"`
	Indeterminate uint64 `json:"indeterminate"`
	KeyCache      int    `json:"key_cache"`
	Lookups       uint64 `json:"lookups"`
}
