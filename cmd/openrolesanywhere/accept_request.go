package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"io/ioutil"
	"math/big"
	"net/url"
	"openrolesanywhere/kmssigner"
	"path/filepath"
	"strings"
	"time"
)

func acceptRequest(ctx context.Context, requestFile string, duration time.Duration, subject pkix.Name) error {
	serialNumber := &big.Int{}
	serialNumber, ok := serialNumber.SetString(subject.SerialNumber, 10)
	if !ok {
		return fmt.Errorf("not a base10 serial number: %s", subject.SerialNumber)
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("loading aws config: %w", err)
	}

	kmsapi := kms.NewFromConfig(cfg)

	caPEM, _ := ioutil.ReadFile(filepath.Join(appDir(), "ca.pem"))
	block, _ := pem.Decode(caPEM)
	ca, _ := x509.ParseCertificate(block.Bytes)

	keyArn := ""
	for _, uri := range ca.URIs {
		if strings.HasPrefix(uri.String(), "arn:aws:kms:") {
			keyArn = uri.String()
		}
	}
	if keyArn == "" {
		panic("key arn not found in CA certificate")
	}

	profileArn, _ := ioutil.ReadFile(filepath.Join(appDir(), "profile-arn.txt"))
	profileArnUrl, _ := url.Parse(string(profileArn))

	trustAnchorArn, _ := ioutil.ReadFile(filepath.Join(appDir(), "trust-anchor-arn.txt"))
	trustAnchorArnUrl, _ := url.Parse(string(trustAnchorArn))

	signer, err := kmssigner.New(ctx, kmsapi, keyArn)
	if err != nil {
		return fmt.Errorf("initializing kms signer: %w", err)
	}

	pubKeyBytes, err := ioutil.ReadFile(requestFile)
	if err != nil {
		return fmt.Errorf("unable to read request-file: %w", err)
	}

	pubDer, _ := pem.Decode(pubKeyBytes)
	publicKey, err := x509.ParsePKIXPublicKey(pubDer.Bytes)
	if err != nil {
		return fmt.Errorf("parsing public key from request: %w", err)
	}

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(duration),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{profileArnUrl, trustAnchorArnUrl},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, publicKey, signer)
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	fmt.Println(string(certPEM))

	return nil
}
