//go:build !linux && !darwin

package mgmt

// peerCredentials is unavailable on this platform: callers are logged as
// unknown and the socket mode remains the only access control.
func peerCredentials(int) PeerCred { return PeerCred{} }
