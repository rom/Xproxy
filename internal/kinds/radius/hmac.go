package radius

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // RFC 3579 specifies HMAC-MD5
)

// hmacMD5 is RFC 3579 §3.2's keyed digest, in one place so the two callers
// that compute it cannot drift.
func hmacMD5(key, msg []byte) []byte {
	h := hmac.New(md5.New, key) //nolint:gosec // RFC 3579 specifies HMAC-MD5
	h.Write(msg)
	return h.Sum(nil)
}
