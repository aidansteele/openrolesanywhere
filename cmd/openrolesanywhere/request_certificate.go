package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func requestCertificate(ctx context.Context, fingerprint string) error {
	signer, err := signerFromFingerprint(fingerprint)
	if err != nil {
		return fmt.Errorf("getting ssh signer: %w", err)
	}

	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("getting public key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})
	fmt.Println(string(certPEM))

	return nil
}
