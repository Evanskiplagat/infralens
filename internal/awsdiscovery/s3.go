package awsdiscovery

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Discoverer collects buckets and their public-access status.
// S3 is a global service, so this discoverer ignores opts.Region for
// listing and only uses it (if set) for credential resolution.
type S3Discoverer struct{}

func (S3Discoverer) Name() string { return "s3" }

// Global marks S3 bucket listing as account-wide, so a multi-region scan
// runs it once rather than once per region.
func (S3Discoverer) Global() bool { return true }

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
			Name:              name,
			PublicAccess:      bucketIsPublic(ctx, client, name),
			BlockPublicAccess: bucketBlocksPublicAccess(ctx, client, name),
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

// bucketBlocksPublicAccess reports whether all four S3 Block Public Access
// settings are enabled on the bucket. It returns nil when the answer cannot
// be determined (for example, the caller lacks s3:GetBucketPublicAccessBlock),
// so findings never treat "unknown" as "unprotected". A bucket with no
// configuration at all is reported as false.
func bucketBlocksPublicAccess(ctx context.Context, client *s3.Client, bucket string) *bool {
	out, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		var coded interface{ ErrorCode() string }
		if errors.As(err, &coded) && coded.ErrorCode() == "NoSuchPublicAccessBlockConfiguration" {
			return aws.Bool(false)
		}
		return nil
	}
	cfg := out.PublicAccessBlockConfiguration
	if cfg == nil {
		return aws.Bool(false)
	}
	all := aws.ToBool(cfg.BlockPublicAcls) &&
		aws.ToBool(cfg.BlockPublicPolicy) &&
		aws.ToBool(cfg.IgnorePublicAcls) &&
		aws.ToBool(cfg.RestrictPublicBuckets)
	return aws.Bool(all)
}
