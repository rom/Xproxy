// Package wafstatus holds the management view of the web application
// firewall as plain data.
//
// It is a leaf: time and nothing else. The types live here rather than
// beside the engine that fills them in because every daemon serves the
// management API, and a type from internal/waf in that surface would
// link Coraza and its rule sets into the SSH bastion and the mail relay,
// which run no WAF at all.
package wafstatus

import "time"

// RuleStat is one rule's counters as reported.
type RuleStat struct {
	ID       int    `json:"id"`
	Message  string `json:"message,omitempty"`
	Severity string `json:"severity,omitempty"`
	// Tags keeps the attack- and paranoia-level tags of the rule.
	Tags []string `json:"tags,omitempty"`
	// Matches counts transactions in which the rule matched. Blocks counts
	// those the WAF denied (block mode); Detects counts those detect mode
	// would have denied.
	Matches  uint64    `json:"matches"`
	Blocks   uint64    `json:"blocks"`
	Detects  uint64    `json:"detects"`
	LastSeen time.Time `json:"last_seen"`
	LastURI  string    `json:"last_uri,omitempty"`
}

// Report is the management view (GET /v1/waf).
type Report struct {
	Since    time.Time `json:"since"`
	Requests uint64    `json:"requests"`
	Blocked  uint64    `json:"blocked"`
	Detected uint64    `json:"detected"`
	// Rules lists the matched rules, most matched first, at most top
	// entries; TotalRules is the number of distinct rules seen and
	// RulesDropped how many matches of further rules the full table
	// could not record.
	Rules        []RuleStat      `json:"rules"`
	TotalRules   int             `json:"total_rules"`
	RulesDropped uint64          `json:"rules_dropped,omitempty"`
	Learning     *LearningReport `json:"learning"`
	// SchemaViolations counts request bodies that failed a profile's
	// json_schemas (denied in block mode, logged in detect mode).
	SchemaViolations uint64         `json:"schema_violations"`
	Anomaly          *AnomalyReport `json:"anomaly"`
}

// LearningReport describes the learning table and its proposals.
type LearningReport struct {
	Enabled    bool       `json:"enabled"`
	MinHits    int        `json:"min_hits"`
	Entries    int        `json:"entries"`
	MaxEntries int        `json:"max_entries"`
	Dropped    uint64     `json:"dropped"`
	Proposals  []Proposal `json:"proposals"`
}

// Proposal is one suggested exclusion: rule ID and target seen together at
// least min_hits times on a route.
type Proposal struct {
	Rule    int    `json:"rule"`
	Message string `json:"message,omitempty"`
	Target  string `json:"target"`
	Route   string `json:"route,omitempty"`
	// Path is the route's path prefix when known, used to scope the
	// generated exclusion; "" scopes it to the whole profile.
	Path      string    `json:"path,omitempty"`
	Hits      uint64    `json:"hits"`
	Clients   int       `json:"clients"`
	LastSeen  time.Time `json:"last_seen"`
	LastURI   string    `json:"last_uri,omitempty"`
	Sample    string    `json:"sample,omitempty"`
	Directive string    `json:"directive"`
}

// AnomalyReport is the management view of the detector.
type AnomalyReport struct {
	Enabled     bool    `json:"enabled"`
	Window      string  `json:"window,omitempty"`
	MinRequests int     `json:"min_requests,omitempty"`
	Threshold   float64 `json:"threshold,omitempty"`
	Action      string  `json:"action,omitempty"`
	// Clients is the number tracked in the current window; Dropped counts
	// clients the full table could not track.
	Clients    int    `json:"clients"`
	MaxClients int    `json:"max_clients,omitempty"`
	Dropped    uint64 `json:"dropped,omitempty"`
	// Windows counts closed windows; Scored is the number of clients the
	// last closed window compared.
	Windows uint64 `json:"windows"`
	Scored  int    `json:"scored"`
	// Flagged is the number of clients currently flagged; FlaggedTotal
	// counts flags raised since the last reset and Acted the requests of
	// flagged clients logged, challenged or blocked.
	Flagged      int               `json:"flagged"`
	FlaggedTotal uint64            `json:"flagged_total"`
	Acted        uint64            `json:"acted"`
	Baseline     []FeatureBaseline `json:"baseline,omitempty"`
	Top          []ClientAnomaly   `json:"top"`
}

// FeatureBaseline is the population statistic of one feature.
type FeatureBaseline struct {
	Feature string  `json:"feature"`
	Mean    float64 `json:"mean"`
	StdDev  float64 `json:"stddev"`
}

// ClientAnomaly is one flagged client.
type ClientAnomaly struct {
	Client  string    `json:"client"`
	Score   float64   `json:"score"`
	Feature string    `json:"feature"`
	Value   float64   `json:"value"`
	Mean    float64   `json:"mean"`
	Since   time.Time `json:"since"`
	Expires time.Time `json:"expires"`
}

// ProfileStatus describes one compiled profile (GET /v1/waf).
type ProfileStatus struct {
	Name  string   `json:"name"`
	Modes []string `json:"modes"`
	// CRS is "embedded", the rule set directory, or "" when the profile
	// has no Core Rule Set.
	CRS string `json:"crs,omitempty"`
	// Version is the CRS setup version (for example "4250" for 4.25.0).
	Version string `json:"version,omitempty"`
	// RuleFiles counts the CRS rule files loaded.
	RuleFiles int `json:"rule_files,omitempty"`
	// Plugins names the CRS plugins loaded.
	Plugins []string `json:"plugins,omitempty"`
	// Schemas names the JSON body schemas enforced.
	Schemas []string `json:"schemas,omitempty"`
}
