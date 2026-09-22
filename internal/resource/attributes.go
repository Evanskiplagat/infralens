package resource

import "encoding/json"

// Recognized Resource.Attributes keys. Producers (normalize) and
// consumers (findings) share these constants so the two stay in sync
// without either package depending on the other's internals.
const (
	AttrCIDRBlock        = "cidr_block"
	AttrIsDefaultVPC     = "is_default_vpc"
	AttrAvailabilityZone = "availability_zone"
	AttrMapPublicIP      = "map_public_ip_on_launch"
	AttrHasIGWRoute      = "has_igw_route"
	AttrIngressRules     = "ingress_rules"
	AttrPublicIP         = "public_ip"
	AttrHasPublicIP      = "has_public_ip"
	AttrState            = "state"
	AttrBucketPublic     = "bucket_public"

	// AttrGroupName is a security group's GroupName (the Name tag, when
	// present, is what Resource.Name carries instead).
	AttrGroupName = "group_name"
	// AttrIsMainRouteTable marks a VPC's main route table, which governs
	// every subnet without an explicit route table association.
	AttrIsMainRouteTable = "is_main_route_table"
	// AttrInstanceType is the EC2 instance type, e.g. "t3.micro".
	AttrInstanceType = "instance_type"
	// AttrIAMInstanceProfile is the ARN of the instance profile attached
	// to an instance, or "" when none is attached.
	AttrIAMInstanceProfile = "iam_instance_profile"
	// AttrIMDSv2Required is true when the instance metadata service only
	// accepts session-token (IMDSv2) requests. It is absent when discovery
	// could not determine the setting, so rules never guess.
	AttrIMDSv2Required = "imds_v2_required"
	// AttrEncrypted reports whether an EBS volume is encrypted.
	AttrEncrypted = "encrypted"
	// AttrSizeGiB is a volume's size in GiB.
	AttrSizeGiB = "size_gib"
	// AttrVolumeType is an EBS volume type, e.g. "gp3".
	AttrVolumeType = "volume_type"
	// AttrPublicAccessBlock is true when all four S3 Block Public Access
	// settings are enabled on the bucket. It is absent when discovery
	// could not determine the setting (for example, access denied).
	AttrPublicAccessBlock = "public_access_block"
)

// SGRule is a single normalized security group ingress rule.
type SGRule struct {
	Protocol string `json:"protocol"`
	FromPort int32  `json:"from_port"`
	ToPort   int32  `json:"to_port"`
	CIDR     string `json:"cidr"`
}

// IngressRules extracts AttrIngressRules from a resource's Attributes.
// A Resource fresh from normalize carries a native []SGRule, but one
// loaded back from storage has round-tripped through JSON and holds
// []any of map[string]any instead; this re-decodes that shape so
// callers (findings rules) don't need to know which case they're in.
func IngressRules(attrs map[string]any) []SGRule {
	raw, ok := attrs[AttrIngressRules]
	if !ok {
		return nil
	}
	if rules, ok := raw.([]SGRule); ok {
		return rules
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var rules []SGRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil
	}
	return rules
}
