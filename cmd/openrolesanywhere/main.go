package main

import (
	"context"
	"crypto/x509/pkix"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"log"
	"net"
	"openrolesanywhere"
	"os"
	"path/filepath"
	"time"
)

func main() {
	root := &cobra.Command{
		Use:   "openrolesanywhere",
		Short: "Open-source implementation of an AWS IAM Roles Anywhere client",
	}

	credentialProcessCmd := &cobra.Command{
		Use:   "credential-process",
		Short: "Invoked by AWS SDK or CLI for access to AWS",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.PersistentFlags().GetString("name")
			roleArn, _ := cmd.PersistentFlags().GetString("role-arn")
			duration, _ := cmd.PersistentFlags().GetDuration("duration")
			return credentialProcess(cmd.Context(), name, roleArn, duration)
		},
	}

	credentialProcessCmd.PersistentFlags().String("name", "", "")
	credentialProcessCmd.PersistentFlags().String("role-arn", "", "")
	credentialProcessCmd.PersistentFlags().Duration("duration", time.Hour, "")

	requestCertificateCmd := &cobra.Command{
		Use:   "request-certificate",
		Short: "Use an SSH key to request an X.509 certificate from an admin",
		RunE: func(cmd *cobra.Command, args []string) error {
			sshFingerprint, _ := cmd.PersistentFlags().GetString("ssh-fingerprint")
			return requestCertificate(cmd.Context(), sshFingerprint)
		},
	}

	requestCertificateCmd.PersistentFlags().String("ssh-fingerprint", "", "")

	adminCmd := &cobra.Command{
		Use:   "admin",
		Short: "Administer access to this AWS account",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	adminCreateCACmd := &cobra.Command{
		Use:   "create-ca",
		Short: "Create a certificate authority and trust anchor from a KMS key",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.PersistentFlags().GetString("name")
			kmsKeyId, _ := cmd.PersistentFlags().GetString("kms-key-id")
			subject := getX509Name(cmd.PersistentFlags())
			validityDuration, _ := cmd.PersistentFlags().GetDuration("validity-duration")
			return createCA(cmd.Context(), name, kmsKeyId, subject, validityDuration)
		},
	}

	adminCreateCACmd.PersistentFlags().String("name", "", "")
	adminCreateCACmd.PersistentFlags().String("kms-key-id", "", "")
	adminCreateCACmd.PersistentFlags().Duration("validity-duration", 365*24*time.Hour, "")

	addX509NameFlags(adminCreateCACmd.PersistentFlags())

	adminCreateProfileCmd := &cobra.Command{
		Use:   "create-profile",
		Short: "Create a profile to allow role assumption",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.PersistentFlags().GetString("name")
			roleArns, _ := cmd.PersistentFlags().GetStringSlice("role-arn")
			duration, _ := cmd.PersistentFlags().GetDuration("session-duration")
			return createProfile(cmd.Context(), name, roleArns, duration)
		},
	}

	adminCreateProfileCmd.PersistentFlags().String("name", "", "")
	adminCreateProfileCmd.PersistentFlags().StringSlice("role-arn", []string{}, "")
	adminCreateProfileCmd.PersistentFlags().Duration("session-duration", time.Hour, "")

	adminAcceptRequestCmd := &cobra.Command{
		Use:   "accept-request",
		Short: "Accept a request for an X.509 certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			requestFile, _ := cmd.PersistentFlags().GetString("request-file")
			subject := getX509Name(cmd.PersistentFlags())
			validityDuration, _ := cmd.PersistentFlags().GetDuration("validity-duration")
			return acceptRequest(cmd.Context(), requestFile, validityDuration, subject)
		},
	}

	adminAcceptRequestCmd.PersistentFlags().String("request-file", "", "")
	adminAcceptRequestCmd.PersistentFlags().Duration("validity-duration", 365*24*time.Hour, "")
	addX509NameFlags(adminAcceptRequestCmd.PersistentFlags())

	adminCmd.AddCommand(
		adminCreateCACmd,
		adminCreateProfileCmd,
		adminAcceptRequestCmd,
	)

	root.AddCommand(
		credentialProcessCmd,
		requestCertificateCmd,
		adminCmd,
	)

	ctx := context.Background()
	err := root.ExecuteContext(ctx)
	if err != nil {
		log.Fatalf("error: %+v", err)
	}
}

func appDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(fmt.Errorf("getting user home dir: %w", err))
	}

	dir := filepath.Join(home, ".config/openrolesanywhere")
	err = os.MkdirAll(dir, 0700)
	if err != nil {
		panic(fmt.Errorf("creating app dir: %w", err))
	}

	return dir
}

func signerFromFingerprint(fingerprint string) (openrolesanywhere.Signer, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("connecting to ssh agent: %w", err)
	}

	agentClient := agent.NewClient(conn)
	signers, err := agentClient.Signers()
	if err != nil {
		return nil, fmt.Errorf("listing signers in ssh agent: %w", err)
	}

	seen := []string{}
	for _, signer := range signers {
		finger := ssh.FingerprintSHA256(signer.PublicKey())
		seen = append(seen, finger)

		if finger == fingerprint {
			algorithmSigner := signer.(ssh.AlgorithmSigner)
			return openrolesanywhere.NewSignerFromSshSigner(algorithmSigner), nil
		}
	}

	return nil, fmt.Errorf("no ssh key found matching fingerprint %s. fingerprints seen: %+v", fingerprint, seen)
}

func addX509NameFlags(f *pflag.FlagSet) {
	f.Int64("serial-number", 0, "")
	f.String("common-name", "", "")
	f.String("organization", "", "")
	f.String("organization-unit", "", "")
	f.String("country", "", "")
	f.String("locality", "", "")
	f.String("province", "", "")
	f.String("street-address", "", "")
	f.String("postal-code", "", "")
}

func getX509Name(f *pflag.FlagSet) pkix.Name {
	serialNumber, _ := f.GetInt64("serial-number")
	commonName, _ := f.GetString("common-name")

	name := pkix.Name{
		SerialNumber: fmt.Sprintf("%d", serialNumber),
		CommonName:   commonName,
	}

	if organization, _ := f.GetString("organization"); organization != "" {
		name.Organization = []string{organization}
	}

	if organizationUnit, _ := f.GetString("organization-unit"); organizationUnit != "" {
		name.OrganizationalUnit = []string{organizationUnit}
	}

	if country, _ := f.GetString("country"); country != "" {
		name.Country = []string{country}
	}

	if locality, _ := f.GetString("locality"); locality != "" {
		name.Locality = []string{locality}
	}

	if province, _ := f.GetString("province"); province != "" {
		name.Province = []string{province}
	}

	if streetAddress, _ := f.GetString("street-address"); streetAddress != "" {
		name.StreetAddress = []string{streetAddress}
	}

	if postalCode, _ := f.GetString("postal-code"); postalCode != "" {
		name.PostalCode = []string{postalCode}
	}

	return name
}
