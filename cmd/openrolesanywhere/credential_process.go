package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"openrolesanywhere"
	"path/filepath"
	"strings"
	"time"
)

func credentialProcess(ctx context.Context, name, roleArn string, duration time.Duration) error {
	certPath := filepath.Join(appDir(), fmt.Sprintf("%s.pem", name))
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("reading certificate file at path %s: %w", certPath, err)
	}

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing certificate file at path %s: %w", certPath, err)
	}

	region := ""
	profileArn := ""
	trustAnchorArn := ""
	for _, uri := range cert.URIs {
		str := uri.String()
		if !strings.HasPrefix(str, "arn:aws:rolesanywhere:") {
			continue
		}

		split := strings.SplitN(str, ":", 6)
		if strings.HasPrefix(split[5], "profile/") {
			region = split[3]
			profileArn = str
		} else if strings.HasPrefix(split[5], "trust-anchor/") {
			trustAnchorArn = str
		}
	}

	if trustAnchorArn == "" || profileArn == "" {
		panic("trust anchor or profile arn not found in certificate")
	}

	sshPub, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("extracting public key from cert: %w", err)
	}

	fingerprint := ssh.FingerprintSHA256(sshPub)
	signer, err := signerFromFingerprint(fingerprint)
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}

	cso, err := openrolesanywhere.CreateSession(ctx, nil, &openrolesanywhere.CreateSessionInput{
		Certificate:     cert,
		Signer:          signer,
		ProfileArn:      profileArn,
		RoleArn:         roleArn,
		TrustAnchorArn:  trustAnchorArn,
		SessionDuration: int(duration.Seconds()),
		Region:          region,
	})
	if err != nil {
		panic(err)
	}

	c := cso.CredentialSet[0].Credentials
	output := credentialProcessOutput{
		Version:         1,
		AccessKeyId:     c.AccessKeyId,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		Expiration:      c.Expiration.Format(time.RFC3339),
	}

	j, _ := json.Marshal(output)
	fmt.Println(string(j))

	return nil
}

type credentialProcessOutput struct {
	Version         int    `json:"Version"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}
