package awsdiscovery

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// CallerAccountID resolves the AWS account ID for the credentials opts
// selects, via STS GetCallerIdentity (a read-only, always-permitted
// call). It's used to tag resources and scans with their account.
func CallerAccountID(ctx context.Context, opts Options) (string, error) {
	cfg, err := LoadAWSConfig(ctx, opts)
	if err != nil {
		return "", err
	}
	client := sts.NewFromConfig(cfg)
	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("get caller identity: %w", err)
	}
	return aws.ToString(out.Account), nil
}
