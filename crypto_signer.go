package openrolesanywhere

import (
	"crypto"
	"crypto/sha256"
	"io"
)

func NewSignerFromCryptoSigner(in crypto.Signer) Signer {
	return &cryptoSigner{Signer: in}
}

type cryptoSigner struct {
	crypto.Signer
}

func (c *cryptoSigner) Sign(rand io.Reader, message []byte) (signature []byte, err error) {
	digest := makeHash(sha256.New(), message)
	return c.Signer.Sign(rand, digest, crypto.SHA256)
}

func (c *cryptoSigner) Public() crypto.PublicKey {
	return c.Signer.Public()
}
