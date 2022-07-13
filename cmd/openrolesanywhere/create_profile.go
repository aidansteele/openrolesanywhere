package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere/types"
	"io/ioutil"
	"path/filepath"
	"time"
)

func createProfile(ctx context.Context, name string, roleArns []string, duration time.Duration) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("loading aws config: %w", err)
	}

	api := rolesanywhere.NewFromConfig(cfg)

	createProfile, err := api.CreateProfile(ctx, &rolesanywhere.CreateProfileInput{
		Name:                      &name,
		RoleArns:                  roleArns,
		DurationSeconds:           aws.Int32(int32(duration.Seconds())),
		Enabled:                   aws.Bool(true),
		RequireInstanceProperties: aws.Bool(false),
		Tags: []types.Tag{
			{Key: aws.String("openrolesanywhere"), Value: aws.String("true")},
			{Key: aws.String("Name"), Value: aws.String(name)},
		},
	})
	if err != nil {
		return fmt.Errorf("creating profile: %w", err)
	}

	err = ioutil.WriteFile(filepath.Join(appDir(), "profile-arn.txt"), []byte(*createProfile.Profile.ProfileArn), 0700)
	if err != nil {
		return fmt.Errorf("writing trust anchor arn to filesystem: %w", err)
	}

	return nil
}
