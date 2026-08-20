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
