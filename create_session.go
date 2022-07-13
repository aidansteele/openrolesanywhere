package openrolesanywhere

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

func CreateSessionRequest(ctx context.Context, input *CreateSessionInput) (*http.Request, error) {
	inputPayload, _ := json.Marshal(map[string]any{"durationSeconds": input.SessionDuration})
	payloadHashHex := hex.EncodeToString(makeHash(sha256.New(), inputPayload))

	q := url.Values{}
	q.Set("profileArn", input.ProfileArn)
	q.Set("roleArn", input.RoleArn)
	q.Set("trustAnchorArn", input.TrustAnchorArn)
	u := fmt.Sprintf("https://rolesanywhere.%s.amazonaws.com/sessions?%s", input.Region, q.Encode())

	r, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(inputPayload))
	if err != nil {
		return nil, fmt.Errorf("creating http request: %w", err)
	}
	r.Header.Set("Content-Type", "application/json")

	err = SignHTTP(
		input.Certificate,
		input.Signer,
		r,
		payloadHashHex,
		"rolesanywhere",
		input.Region,
		time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("signing http request: %w", err)
	}

	return r, nil
}

func CreateSession(ctx context.Context, client *http.Client, input *CreateSessionInput) (*CreateSessionOutput, error) {
	r, err := CreateSessionRequest(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(r)
	if err != nil {
		return nil, fmt.Errorf("sending http request: %w", err)
	}

	defer resp.Body.Close()
	rbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	cso := CreateSessionOutput{}
	err = json.Unmarshal(rbody, &cso)
	if err != nil {
		return nil, fmt.Errorf("parsing response json: %w", err)
	}

	return &cso, nil
}

type CreateSessionInput struct {
	Certificate     *x509.Certificate
	Signer          Signer
	ProfileArn      string
	RoleArn         string
	TrustAnchorArn  string
	SessionDuration int
	Region          string
}

type CreateSessionOutput struct {
	CredentialSet []CredentialSet `json:"credentialSet"`
	EnrollmentArn string          `json:"enrollmentArn"`
	SubjectArn    string          `json:"subjectArn"`
}

type Credentials struct {
	AccessKeyId     string    `json:"accessKeyId"`
	Expiration      time.Time `json:"expiration"`
	SecretAccessKey string    `json:"secretAccessKey"`
	SessionToken    string    `json:"sessionToken"`
}

type AssumedRoleUser struct {
	Arn           string `json:"arn"`
	AssumedRoleId string `json:"assumedRoleId"`
}

type CredentialSet struct {
	AssumedRoleUser  AssumedRoleUser `json:"assumedRoleUser"`
	Credentials      Credentials     `json:"credentials"`
	PackedPolicySize int             `json:"packedPolicySize"`
	RoleArn          string          `json:"roleArn"`
	SourceIdentity   string          `json:"sourceIdentity"`
}
