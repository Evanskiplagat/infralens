package awsdiscovery

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// LoadAWSConfig resolves AWS credentials and region using the standard
// SDK chain (environment, shared config/credentials files, an assumed
// role, or an instance/task role), scoped by opts.
func LoadAWSConfig(ctx context.Context, opts Options) (aws.Config, error) {
	var optFns []func(*config.LoadOptions) error
	if opts.Profile != "" {
		optFns = append(optFns, config.WithSharedConfigProfile(opts.Profile))
	}
	if opts.Region != "" {
		optFns = append(optFns, config.WithRegion(opts.Region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS config: %w", err)
	}
	return cfg, nil
}
