package awsdiscovery

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Discoverer collects buckets and their public-access status.
// S3 is a global service, so this discoverer ignores opts.Region for
// listing and only uses it (if set) for credential resolution.
type S3Discoverer struct{}

func (S3Discoverer) Name() string { return "s3" }

func (S3Discoverer) Discover(ctx context.Context, opts Options, snap *Snapshot) error {
	cfg, err := LoadAWSConfig(ctx, opts)
	if err != nil {
		return err
	}
	client := s3.NewFromConfig(cfg)

	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("list buckets: %w", err)
	}

	for _, b := range out.Buckets {
		name := aws.ToString(b.Name)
		if name == "" {
			continue
		}
		snap.S3Buckets = append(snap.S3Buckets, S3Bucket{
			Name:         name,
			PublicAccess: bucketIsPublic(ctx, client, name),
		})
	}
	return nil
}

// bucketIsPublic asks S3 to evaluate its own bucket policy for public
// access. A bucket with no policy (or a permissions error checking it)
// is conservatively treated as not public via this signal; ACL-based
// public access is a follow-on discovery improvement (see roadmap).
func bucketIsPublic(ctx context.Context, client *s3.Client, bucket string) bool {
	status, err := client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
		Bucket: aws.String(bucket),
	})
	if err != nil || status.PolicyStatus == nil {
		return false
	}
	return aws.ToBool(status.PolicyStatus.IsPublic)
}
