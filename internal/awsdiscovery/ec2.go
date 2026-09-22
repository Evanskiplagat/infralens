package awsdiscovery

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EC2Discoverer collects VPCs, subnets, route tables, internet
// gateways, security groups, and instances for one region.
type EC2Discoverer struct{}

func (EC2Discoverer) Name() string { return "ec2" }

func (EC2Discoverer) Discover(ctx context.Context, opts Options, snap *Snapshot) error {
	cfg, err := LoadAWSConfig(ctx, opts)
	if err != nil {
		return err
	}
	client := ec2.NewFromConfig(cfg)
	region := cfg.Region

	// Optional steps cover data added after InfraLens's original permission
	// set. When the caller's role predates them, the step is skipped with a
	// warning instead of failing the whole region and discarding the VPCs,
	// instances and security groups that were readable.
	steps := []struct {
		name     string
		run      func(context.Context, *ec2.Client, string, *Snapshot) error
		optional bool
	}{
		{"vpcs", discoverVPCs, false},
		{"subnets", discoverSubnets, false},
		{"route tables", discoverRouteTables, false},
		{"internet gateways", discoverInternetGateways, false},
		{"security groups", discoverSecurityGroups, false},
		{"instances", discoverInstances, false},
		{"volumes", discoverVolumes, true},
	}
	for _, step := range steps {
		if err := step.run(ctx, client, region, snap); err != nil {
			if step.optional && IsAccessDenied(err) {
				snap.Warnings = append(snap.Warnings, fmt.Sprintf(
					"ec2 in %s: skipped %s because access was denied (%v); grant the permission to include them", region, step.name, err))
				continue
			}
			return err
		}
	}
	return nil
}

func tagsToMap(tags []types.Tag) map[string]string {
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		if t.Key != nil && t.Value != nil {
			m[*t.Key] = *t.Value
		}
	}
	return m
}

func discoverVPCs(ctx context.Context, client *ec2.Client, region string, snap *Snapshot) error {
	paginator := ec2.NewDescribeVpcsPaginator(client, &ec2.DescribeVpcsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe vpcs: %w", err)
		}
		for _, v := range page.Vpcs {
			snap.VPCs = append(snap.VPCs, VPC{
				ID:        aws.ToString(v.VpcId),
				CIDRBlock: aws.ToString(v.CidrBlock),
				IsDefault: aws.ToBool(v.IsDefault),
				Tags:      tagsToMap(v.Tags),
				Region:    region,
			})
		}
	}
	return nil
}

func discoverSubnets(ctx context.Context, client *ec2.Client, region string, snap *Snapshot) error {
	paginator := ec2.NewDescribeSubnetsPaginator(client, &ec2.DescribeSubnetsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe subnets: %w", err)
		}
		for _, s := range page.Subnets {
			snap.Subnets = append(snap.Subnets, Subnet{
				ID:                  aws.ToString(s.SubnetId),
				VPCID:               aws.ToString(s.VpcId),
				CIDRBlock:           aws.ToString(s.CidrBlock),
				AvailabilityZone:    aws.ToString(s.AvailabilityZone),
				MapPublicIPOnLaunch: aws.ToBool(s.MapPublicIpOnLaunch),
				Tags:                tagsToMap(s.Tags),
				Region:              region,
			})
		}
	}
	return nil
}

func discoverRouteTables(ctx context.Context, client *ec2.Client, region string, snap *Snapshot) error {
	paginator := ec2.NewDescribeRouteTablesPaginator(client, &ec2.DescribeRouteTablesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe route tables: %w", err)
		}
		for _, rt := range page.RouteTables {
			var subnetIDs []string
			for _, assoc := range rt.Associations {
				if assoc.SubnetId != nil {
					subnetIDs = append(subnetIDs, *assoc.SubnetId)
				}
			}
			isMain := false
			for _, assoc := range rt.Associations {
				if aws.ToBool(assoc.Main) {
					isMain = true
				}
			}
			hasIGWRoute := false
			for _, route := range rt.Routes {
				if gw := aws.ToString(route.GatewayId); strings.HasPrefix(gw, "igw-") {
					hasIGWRoute = true
					break
				}
			}
			snap.RouteTables = append(snap.RouteTables, RouteTable{
				ID:          aws.ToString(rt.RouteTableId),
				VPCID:       aws.ToString(rt.VpcId),
				SubnetIDs:   subnetIDs,
				HasIGWRoute: hasIGWRoute,
				IsMain:      isMain,
				Tags:        tagsToMap(rt.Tags),
				Region:      region,
			})
		}
	}
	return nil
}

func discoverInternetGateways(ctx context.Context, client *ec2.Client, region string, snap *Snapshot) error {
	paginator := ec2.NewDescribeInternetGatewaysPaginator(client, &ec2.DescribeInternetGatewaysInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe internet gateways: %w", err)
		}
		for _, igw := range page.InternetGateways {
			var vpcIDs []string
			for _, att := range igw.Attachments {
				if att.VpcId != nil {
					vpcIDs = append(vpcIDs, *att.VpcId)
				}
			}
			snap.InternetGateways = append(snap.InternetGateways, InternetGateway{
				ID:     aws.ToString(igw.InternetGatewayId),
				VPCIDs: vpcIDs,
				Tags:   tagsToMap(igw.Tags),
				Region: region,
			})
		}
	}
	return nil
}

func discoverSecurityGroups(ctx context.Context, client *ec2.Client, region string, snap *Snapshot) error {
	paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe security groups: %w", err)
		}
		for _, sg := range page.SecurityGroups {
			var ingress []SecurityGroupRule
			var referenced []string
			for _, perm := range sg.IpPermissions {
				for _, pair := range perm.UserIdGroupPairs {
					ref := aws.ToString(pair.GroupId)
					if ref != "" && ref != aws.ToString(sg.GroupId) && !slices.Contains(referenced, ref) {
						referenced = append(referenced, ref)
					}
				}
				for _, r := range perm.IpRanges {
					ingress = append(ingress, SecurityGroupRule{
						Protocol: aws.ToString(perm.IpProtocol),
						FromPort: aws.ToInt32(perm.FromPort),
						ToPort:   aws.ToInt32(perm.ToPort),
						CIDR:     aws.ToString(r.CidrIp),
					})
				}
				for _, r := range perm.Ipv6Ranges {
					ingress = append(ingress, SecurityGroupRule{
						Protocol: aws.ToString(perm.IpProtocol),
						FromPort: aws.ToInt32(perm.FromPort),
						ToPort:   aws.ToInt32(perm.ToPort),
						CIDR:     aws.ToString(r.CidrIpv6),
					})
				}
			}
			snap.SecurityGroups = append(snap.SecurityGroups, SecurityGroup{
				ID:                 aws.ToString(sg.GroupId),
				VPCID:              aws.ToString(sg.VpcId),
				Name:               aws.ToString(sg.GroupName),
				Ingress:            ingress,
				ReferencedGroupIDs: referenced,
				Tags:               tagsToMap(sg.Tags),
				Region:             region,
			})
		}
	}
	return nil
}

func discoverInstances(ctx context.Context, client *ec2.Client, region string, snap *Snapshot) error {
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe instances: %w", err)
		}
		for _, res := range page.Reservations {
			for _, inst := range res.Instances {
				var sgIDs []string
				for _, sg := range inst.SecurityGroups {
					if sg.GroupId != nil {
						sgIDs = append(sgIDs, *sg.GroupId)
					}
				}
				state := ""
				if inst.State != nil {
					state = string(inst.State.Name)
				}
				httpTokens := ""
				if inst.MetadataOptions != nil {
					httpTokens = string(inst.MetadataOptions.HttpTokens)
				}
				profileARN := ""
				if inst.IamInstanceProfile != nil {
					profileARN = aws.ToString(inst.IamInstanceProfile.Arn)
				}
				snap.Instances = append(snap.Instances, Instance{
					InstanceType:          string(inst.InstanceType),
					IAMInstanceProfileARN: profileARN,
					HTTPTokens:            httpTokens,
					ID:                    aws.ToString(inst.InstanceId),
					VPCID:                 aws.ToString(inst.VpcId),
					SubnetID:              aws.ToString(inst.SubnetId),
					SecurityGroupIDs:      sgIDs,
					PublicIP:              aws.ToString(inst.PublicIpAddress),
					PrivateIP:             aws.ToString(inst.PrivateIpAddress),
					State:                 state,
					Tags:                  tagsToMap(inst.Tags),
					Region:                region,
				})
			}
		}
	}
	return nil
}

func discoverVolumes(ctx context.Context, client *ec2.Client, region string, snap *Snapshot) error {
	paginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe volumes: %w", err)
		}
		for _, v := range page.Volumes {
			var attached []string
			for _, a := range v.Attachments {
				if a.InstanceId != nil {
					attached = append(attached, *a.InstanceId)
				}
			}
			snap.Volumes = append(snap.Volumes, Volume{
				ID:                  aws.ToString(v.VolumeId),
				Encrypted:           aws.ToBool(v.Encrypted),
				SizeGiB:             aws.ToInt32(v.Size),
				VolumeType:          string(v.VolumeType),
				AttachedInstanceIDs: attached,
				Tags:                tagsToMap(v.Tags),
				Region:              region,
			})
		}
	}
	return nil
}
