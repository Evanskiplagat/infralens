// Package awsdiscovery talks to the AWS SDK using read-only API calls
// and collects raw, service-specific data into a Snapshot. It is the
// only package permitted to import the AWS SDK; everything downstream
// works with the plain Go structs defined here, converted into the
// normalized resource model by the normalize package.
package awsdiscovery

// VPC is a raw discovered VPC.
type VPC struct {
	ID        string
	CIDRBlock string
	IsDefault bool
	Tags      map[string]string
	Region    string
}

// Subnet is a raw discovered subnet.
type Subnet struct {
	ID                  string
	VPCID               string
	CIDRBlock           string
	AvailabilityZone    string
	MapPublicIPOnLaunch bool
	Tags                map[string]string
	Region              string
}

// RouteTable is a raw discovered route table. HasIGWRoute is true when
// any route targets an internet gateway, which findings rules use as a
// signal for "this subnet can reach the internet."
type RouteTable struct {
	ID          string
	VPCID       string
	SubnetIDs   []string
	HasIGWRoute bool
	// IsMain is true for the VPC's main route table, which governs every
	// subnet that has no explicit association.
	IsMain bool
	Tags   map[string]string
	Region string
}

// InternetGateway is a raw discovered internet gateway.
type InternetGateway struct {
	ID     string
	VPCIDs []string
	Tags   map[string]string
	Region string
}

// SecurityGroupRule is a single raw ingress rule.
type SecurityGroupRule struct {
	Protocol string
	FromPort int32
	ToPort   int32
	CIDR     string
}

// SecurityGroup is a raw discovered security group.
type SecurityGroup struct {
	ID      string
	VPCID   string
	Name    string
	Ingress []SecurityGroupRule
	// ReferencedGroupIDs are the security groups named as a traffic source
	// in this group's ingress rules.
	ReferencedGroupIDs []string
	Tags               map[string]string
	Region             string
}

// Instance is a raw discovered EC2 instance.
type Instance struct {
	ID               string
	VPCID            string
	SubnetID         string
	SecurityGroupIDs []string
	PublicIP         string
	PrivateIP        string
	State            string
	InstanceType     string
	// IAMInstanceProfileARN is empty when no instance profile is attached.
	IAMInstanceProfileARN string
	// HTTPTokens is the instance metadata service token requirement,
	// "required" (IMDSv2 only) or "optional" (IMDSv1 allowed). It is empty
	// when the API did not report it.
	HTTPTokens string
	Tags       map[string]string
	Region     string
}

// S3Bucket is a raw discovered S3 bucket. PublicAccess reflects the
// bucket policy status as reported by S3's own public-access evaluation.
type S3Bucket struct {
	Name         string
	Region       string
	PublicAccess bool
	// BlockPublicAccess is true when all four S3 Block Public Access
	// settings are enabled, false when any is not, and nil when it could
	// not be determined (for example, access denied).
	BlockPublicAccess *bool
	Tags              map[string]string
}

// Volume is a raw discovered EBS volume.
type Volume struct {
	ID                  string
	Encrypted           bool
	SizeGiB             int32
	VolumeType          string
	AttachedInstanceIDs []string
	Tags                map[string]string
	Region              string
}

// Snapshot is the aggregate raw discovery output for a single scan.
// Discoverers append to it; normalize.Normalize consumes it whole.
type Snapshot struct {
	VPCs             []VPC
	Subnets          []Subnet
	RouteTables      []RouteTable
	InternetGateways []InternetGateway
	SecurityGroups   []SecurityGroup
	Instances        []Instance
	Volumes          []Volume
	S3Buckets        []S3Bucket
	// Warnings describe optional data that was skipped, such as a service
	// call the caller's role is not permitted to make. They do not make a
	// scan partial, but the CLI surfaces them so missing coverage is visible.
	Warnings []string
}

// Merge appends everything discovered in other to s. Discovery tasks for
// different regions and services each fill their own Snapshot; merging them
// in a fixed order afterwards keeps scan output deterministic.
func (s *Snapshot) Merge(other *Snapshot) {
	if other == nil {
		return
	}
	s.VPCs = append(s.VPCs, other.VPCs...)
	s.Subnets = append(s.Subnets, other.Subnets...)
	s.RouteTables = append(s.RouteTables, other.RouteTables...)
	s.InternetGateways = append(s.InternetGateways, other.InternetGateways...)
	s.SecurityGroups = append(s.SecurityGroups, other.SecurityGroups...)
	s.Instances = append(s.Instances, other.Instances...)
	s.Volumes = append(s.Volumes, other.Volumes...)
	s.S3Buckets = append(s.S3Buckets, other.S3Buckets...)
	s.Warnings = append(s.Warnings, other.Warnings...)
}
