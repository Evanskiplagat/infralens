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
	Tags        map[string]string
	Region      string
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
	Tags    map[string]string
	Region  string
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
	Tags             map[string]string
	Region           string
}

// S3Bucket is a raw discovered S3 bucket. PublicAccess reflects the
// bucket policy status as reported by S3's own public-access evaluation.
type S3Bucket struct {
	Name         string
	Region       string
	PublicAccess bool
	Tags         map[string]string
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
	S3Buckets        []S3Bucket
}
