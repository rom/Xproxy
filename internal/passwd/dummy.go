package passwd

import "sync"

var (
	dummyOnce sync.Once
	dummyHash string
)

// VerifyDummy spends the cost of one real verification against a throwaway
// hash. Callers use it when the user name is unknown, so that an unknown
// name and a wrong password take the same time and the users file cannot
// be enumerated by timing. The result is always false.
func VerifyDummy(password string) bool {
	dummyOnce.Do(func() { dummyHash, _ = Hash("xproxy-dummy-verification") })
	if dummyHash == "" {
		return false
	}
	Verify(dummyHash, password)
	return false
}
