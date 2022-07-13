package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere/types"
	"io/ioutil"
	"math/big"
	"net/url"
	"openrolesanywhere/kmssigner"
	"path/filepath"
	"time"
)

func createCA(ctx context.Context, name, keyId string, subject pkix.Name, duration time.Duration) error {
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

	describeKey, err := kmsapi.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &keyId})
	if err != nil {
		return fmt.Errorf("describing kms key: %w", err)
	}

	keyArn := *describeKey.KeyMetadata.Arn
	keyArnUrl, _ := url.Parse(keyArn)

	signer, err := kmssigner.New(ctx, kmsapi, keyArn)
	if err != nil {
		return fmt.Errorf("initializing kms signer: %w", err)
	}

	ca := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(duration),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		URIs:                  []*url.URL{keyArnUrl},
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, signer.Public(), signer)
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	err = ioutil.WriteFile(filepath.Join(appDir(), "ca.pem"), certPEM, 0700)
	if err != nil {
		return fmt.Errorf("writing certificate to filesystem: %w", err)
	}

	api := rolesanywhere.NewFromConfig(cfg)
	trustAnchor, err := api.CreateTrustAnchor(ctx, &rolesanywhere.CreateTrustAnchorInput{
		Name:    &name,
		Enabled: aws.Bool(true),
		Source: &types.Source{
			SourceData: &types.SourceDataMemberX509CertificateData{Value: string(certPEM)},
			SourceType: types.TrustAnchorTypeCertificateBundle,
		},
		Tags: []types.Tag{
			{Key: aws.String("openrolesanywhere"), Value: aws.String("true")},
			{Key: aws.String("Name"), Value: aws.String(name)},
		},
	})
	if err != nil {
		return fmt.Errorf("creating trust anchor: %w", err)
	}

	err = ioutil.WriteFile(filepath.Join(appDir(), "trust-anchor-arn.txt"), []byte(*trustAnchor.TrustAnchor.TrustAnchorArn), 0700)
	if err != nil {
		return fmt.Errorf("writing trust anchor arn to filesystem: %w", err)
	}

	return nil
}
