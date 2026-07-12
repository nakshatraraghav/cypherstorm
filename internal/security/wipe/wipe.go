// Package wipe provides best-effort clearing for mutable secret byte slices.
// Go cannot guarantee that compiler/runtime copies are cleared; callers must
// avoid storing secrets in immutable strings and clear every owned []byte.
package wipe

// Bytes overwrites b in place. It is safe for nil and empty slices.
func Bytes(b []byte) {
	clear(b)
}
