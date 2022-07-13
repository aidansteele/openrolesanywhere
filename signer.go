package openrolesanywhere

import (
	"crypto"
	"io"
)

// Signer is almost identical to crypto.Signer, but it expects to receive the
// raw message to be signed (rather than its digest). This is because ssh.Signer
// expects a raw undigested message too.
type Signer interface {
	Public() crypto.PublicKey
	Sign(rand io.Reader, undigestedMessage []byte) (signature []byte, err error)
}
