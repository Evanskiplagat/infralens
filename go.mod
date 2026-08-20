// This module was authored in an environment without a Go toolchain
// installed, so dependency checksums (go.sum) could not be generated here.
// Run `go mod tidy` in a Go 1.23+ environment before the first build; it
// will fetch these modules and write go.sum.
module infralens

go 1.23

require (
	github.com/aws/aws-sdk-go-v2 v1.30.3
	github.com/aws/aws-sdk-go-v2/config v1.27.27
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.180.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.58.2
	github.com/aws/aws-sdk-go-v2/service/sts v1.30.3
	modernc.org/sqlite v1.29.10
)
