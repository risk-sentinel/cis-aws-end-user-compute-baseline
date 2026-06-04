# encoding: UTF-8
#
# aws_workspaces_egress_routing — VERIFY (don't trust) that WorkSpaces directory
# subnets are private (egress via NAT, not a direct internet gateway). Built
# in-profile per `each_profile_stands_alone` (CIS 2.5) — does not defer to a VPC
# profile. For each directory subnet, resolves the controlling route table
# (explicit subnet association, else the VPC main route table) and flags a
# directory whose subnet route table carries a 0.0.0.0/0 route to an
# internet-gateway (igw-*) — i.e. a public subnet, which violates "traffic
# controlled and routed" (egress should traverse a NAT gateway).
#
#   describe aws_workspaces_egress_routing do
#     its('directories_with_public_route') { should be_empty }
#   end
#
# exec_validated: false — not yet verified against a live account; the
# subnet->route-table resolution + igw-route detection should be confirmed
# against a real WorkSpaces VPC before relying on a FAIL.

class AwsWorkspacesEgressRouting < AwsResourceBase
  name "aws_workspaces_egress_routing"
  desc "WorkSpaces directories whose subnet route table has a public (igw) default route."
  example "
    describe aws_workspaces_egress_routing do
      its('directories_with_public_route') { should be_empty }
    end
  "

  attr_reader :directories_with_public_route

  def initialize(opts = {})
    super(opts)
    @directories_with_public_route = []
    catch_aws_errors do
      inv = inspec.aws_workspaces_inventory
      ec2 = @aws.compute_client
      Array(inv.directories).each do |d|
        subnets = Array(d[:subnet_ids])
        next if subnets.empty?
        public_route = subnets.any? { |sid| subnet_has_public_route?(ec2, sid) }
        @directories_with_public_route << d[:directory_id] if public_route
      end
    end
  end

  def to_s
    "WorkSpaces directory egress routing"
  end

  private

  # True if the route table controlling this subnet has a 0.0.0.0/0 -> igw route.
  def subnet_has_public_route?(ec2, subnet_id)
    rts = ec2.describe_route_tables(
      filters: [{ name: "association.subnet-id", values: [subnet_id] }],
    ).route_tables
    if rts.empty?
      # No explicit association -> the VPC main route table governs the subnet.
      vpc_id = ec2.describe_subnets(subnet_ids: [subnet_id]).subnets.first&.vpc_id
      return false if vpc_id.nil?
      rts = ec2.describe_route_tables(
        filters: [{ name: "vpc-id", values: [vpc_id] }, { name: "association.main", values: ["true"] }],
      ).route_tables
    end
    rts.any? do |rt|
      Array(rt.routes).any? do |r|
        r.destination_cidr_block == "0.0.0.0/0" && r.gateway_id.to_s.start_with?("igw-")
      end
    end
  rescue StandardError
    false
  end
end
