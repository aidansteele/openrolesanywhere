package openrolesanywhere

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"math/big"
)

func NewSignerFromSshSigner(in ssh.AlgorithmSigner) Signer {
	return &sshSigner{AlgorithmSigner: in}
}

type sshSigner struct {
	ssh.AlgorithmSigner
}

func (s *sshSigner) Sign(rand io.Reader, message []byte) (signature []byte, err error) {
	typ := s.AlgorithmSigner.PublicKey().Type()

	switch typ {
	case ssh.KeyAlgoRSA:
		sig, err := s.AlgorithmSigner.SignWithAlgorithm(rand, message, ssh.KeyAlgoRSASHA256)
		if err != nil {
			return nil, fmt.Errorf("rsa-sha2-256 signing: %w", err)
		}

		return sig.Blob, nil
	case ssh.KeyAlgoECDSA256:
		type asn1Signature struct {
			R, S *big.Int
		}

		sig, err := s.AlgorithmSigner.SignWithAlgorithm(rand, message, ssh.KeyAlgoECDSA256)
		if err != nil {
			return nil, fmt.Errorf("ssh signing: %w", err)
		}

		asn1Sig := asn1Signature{}
		err = ssh.Unmarshal(sig.Blob, &asn1Sig)
		if err != nil {
			return nil, fmt.Errorf("unmarshalling ssh signature: %w", err)
		}

		realsig, err := asn1.Marshal(asn1Sig)
		if err != nil {
			return nil, fmt.Errorf("remarshalling crypto signature: %w", err)
		}

		return realsig, nil
	default:
		return nil, fmt.Errorf("unexpected ssh key type: %s", typ)
	}
}

func (s *sshSigner) Public() crypto.PublicKey {
	//return s.AlgorithmSigner.PublicKey().(ssh.CryptoPublicKey).CryptoPublicKey()

	// we have to round-trip because the agent's key doesn't implement
	// ssh.CryptoPublicKey. maybe i should file a golang feature request?
	authorized := ssh.MarshalAuthorizedKey(s.AlgorithmSigner.PublicKey())
	pub, _, _, _, err := ssh.ParseAuthorizedKey(authorized)
	if err != nil {
		panic(err)
	}

	return pub.(ssh.CryptoPublicKey).CryptoPublicKey()
}
