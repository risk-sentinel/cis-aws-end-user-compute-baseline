# Account-wide enumeration of AWS AppStream 2.0 fleets, image-builders,
# and (joining with EC2) AppStream VPC interface endpoints. For
# cis-aws-end-user-compute C-5.1 / C-5.2 / C-5.6.
#
# Per-region client instantiation rather than @aws.aws_client(klass)
# (consistent with aws_iam_access_analyzers / aws_workspaces_web_inventory).
#
# C-5.1 (Ensure AppStream is using its own VPC) — every fleet AND image-
# builder must have a `vpc_config` populated.
#
# C-5.2 (Ensure VPC Endpoint is set for AppStream) — the consumer's
# AppStream VPCs must each contain at least one Available
# `appstream.<region>.amazonaws.com` interface endpoint. We join AppStream
# fleets/builders to their VPC IDs, then check ec2.describe_vpc_endpoints
# in the same region.
#
# C-5.6 (Ensure internet access is granted and managed through your VPC)
# — AppStream fleets have a `enable_default_internet_access` flag that
# defaults to false; when false, internet egress is routed through the
# customer VPC's NAT gateway / VPC peering. Setting it to true uses
# AppStream's managed default internet path (out of customer's network
# governance). The control flags fleets where this flag is true.
#
# Defensive `aws-sdk-appstream` require — see aws_workspaces_web_inventory.rb
# for the connection_error fallback rationale.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsAppStreamInventory < AwsResourceBase
  name "aws_appstream_inventory"
  desc "AWS AppStream 2.0 fleets + image-builders + VPC-endpoint coverage."
  example "
    inv = aws_appstream_inventory
    if inv.connection_error
      describe inv do; skip 'attestation-required: ...'; end
    else
      describe inv do
        its('fleets_without_vpc_config')               { should be_empty }
        its('image_builders_without_vpc_config')       { should be_empty }
        its('vpcs_without_appstream_endpoint')         { should be_empty }
        its('fleets_using_default_internet_access')    { should be_empty }
      end
    end
  "

  attr_reader :fleets,
              :image_builders,
              :fleets_without_vpc_config,
              :image_builders_without_vpc_config,
              :vpcs_without_appstream_endpoint,
              :fleets_using_default_internet_access,
              :fleets_with_excessive_session_duration,
              :fleets_with_excessive_disconnect_timeout,
              :fleets_with_excessive_idle_disconnect_timeout,
              :connection_error

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @max_session_duration_seconds = (opts.delete(:max_session_duration_seconds) || 36_000).to_i        # 10h per CIS §5.3
    @max_disconnect_timeout_seconds = (opts.delete(:max_disconnect_timeout_seconds) || 300).to_i      # 5min per CIS §5.4
    @max_idle_disconnect_seconds = (opts.delete(:max_idle_disconnect_seconds) || 600).to_i            # 10min per CIS §5.5
    @fleets = []
    @image_builders = []
    @fleets_without_vpc_config = []
    @image_builders_without_vpc_config = []
    @vpcs_without_appstream_endpoint = []
    @fleets_using_default_internet_access = []
    @fleets_with_excessive_session_duration = []
    @fleets_with_excessive_disconnect_timeout = []
    @fleets_with_excessive_idle_disconnect_timeout = []
    @connection_error = nil
    begin
      require "aws-sdk-appstream"
    rescue LoadError => e
      @connection_error = "aws-sdk-appstream not installed: #{e.message}. Use risksentinel/cinc-auditor extended image (your CI image-bake tracker) or attest separately."
      return
    end
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    @connection_error.nil?
  end

  def to_s
    "AWS AppStream 2.0 inventory"
  end

  # Image builders whose creation time is older than `days` — proxy for stale
  # AppStream image OS-update cadence (CIS 5.7). created_time is the builder
  # creation timestamp from describe_image_builders.
  def image_builders_older_than(days)
    cutoff = Time.now - (days.to_i * 86_400)
    Array(@image_builders).select { |b| b[:created_time] && b[:created_time] < cutoff }
  end

  private

  def fetch_default_regions
    regions = []
    catch_aws_errors do
      regions = @aws.compute_client.describe_regions.regions.map(&:region_name)
    end
    regions
  end

  def fetch_data
    @regions.each do |region|
      walk_region(region)
    end
  end

  def walk_region(region)
    client = ::Aws::AppStream::Client.new(region: region)
    fleet_vpcs = walk_fleets(client, region)
    builder_vpcs = walk_image_builders(client, region)
    consumer_vpcs = (fleet_vpcs + builder_vpcs).uniq
    return if consumer_vpcs.empty?
    check_vpc_endpoints(region, consumer_vpcs)
  rescue ::Aws::Errors::ServiceError => e
    Inspec::Log.warn("aws_appstream_inventory: #{region} fetch failed: #{e.message}")
  end

  def walk_fleets(client, region)
    vpcs = []
    next_token = nil
    loop do
      resp =
        begin
          client.describe_fleets(next_token: next_token)
        rescue ::Aws::Errors::ServiceError => e
          Inspec::Log.warn("aws_appstream_inventory: #{region} describe_fleets failed: #{e.message}")
          return vpcs
        end
      Array(resp.fleets).each do |f|
        record = { region: region, name: f.name, vpc_config: f.vpc_config&.to_h }
        @fleets << record
        if f.vpc_config.nil? || Array(f.vpc_config&.subnet_ids).empty?
          @fleets_without_vpc_config << record
        else
          subnet_to_vpc(region, Array(f.vpc_config.subnet_ids)).tap { |vs| vpcs.concat(vs) }
        end
        if f.respond_to?(:enable_default_internet_access) && f.enable_default_internet_access
          @fleets_using_default_internet_access << record
        end

        # CIS §5.3 / §5.4 / §5.5 — session timeout thresholds.
        if f.respond_to?(:max_user_duration_in_seconds) &&
           f.max_user_duration_in_seconds.to_i > @max_session_duration_seconds
          @fleets_with_excessive_session_duration << record.merge(value_seconds: f.max_user_duration_in_seconds)
        end
        if f.respond_to?(:disconnect_timeout_in_seconds) &&
           f.disconnect_timeout_in_seconds.to_i > @max_disconnect_timeout_seconds
          @fleets_with_excessive_disconnect_timeout << record.merge(value_seconds: f.disconnect_timeout_in_seconds)
        end
        if f.respond_to?(:idle_disconnect_timeout_in_seconds) &&
           f.idle_disconnect_timeout_in_seconds.to_i > @max_idle_disconnect_seconds
          @fleets_with_excessive_idle_disconnect_timeout << record.merge(value_seconds: f.idle_disconnect_timeout_in_seconds)
        end
      end
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
    vpcs.uniq
  end

  def walk_image_builders(client, region)
    vpcs = []
    next_token = nil
    loop do
      resp =
        begin
          client.describe_image_builders(next_token: next_token)
        rescue ::Aws::Errors::ServiceError => e
          Inspec::Log.warn("aws_appstream_inventory: #{region} describe_image_builders failed: #{e.message}")
          return vpcs
        end
      Array(resp.image_builders).each do |b|
        record = { region: region, name: b.name, created_time: b.created_time, vpc_config: b.vpc_config&.to_h }
        @image_builders << record
        if b.vpc_config.nil? || Array(b.vpc_config&.subnet_ids).empty?
          @image_builders_without_vpc_config << record
        else
          subnet_to_vpc(region, Array(b.vpc_config.subnet_ids)).tap { |vs| vpcs.concat(vs) }
        end
      end
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
    vpcs.uniq
  end

  def subnet_to_vpc(region, subnet_ids)
    return [] if subnet_ids.empty?
    ec2 = ::Aws::EC2::Client.new(region: region)
    resp =
      begin
        ec2.describe_subnets(subnet_ids: subnet_ids)
      rescue ::Aws::Errors::ServiceError => e
        Inspec::Log.warn("aws_appstream_inventory: #{region} describe_subnets failed: #{e.message}")
        return []
      end
    Array(resp.subnets).map(&:vpc_id).uniq
  end

  def check_vpc_endpoints(region, vpc_ids)
    ec2 = ::Aws::EC2::Client.new(region: region)
    service_name = "com.amazonaws.#{region}.appstream.api"
    resp =
      begin
        ec2.describe_vpc_endpoints(
          filters: [
            { name: "service-name", values: [service_name] },
            { name: "vpc-endpoint-state", values: ["available"] },
          ],
        )
      rescue ::Aws::Errors::ServiceError => e
        Inspec::Log.warn("aws_appstream_inventory: #{region} describe_vpc_endpoints failed: #{e.message}")
        vpc_ids.each { |v| @vpcs_without_appstream_endpoint << { region: region, vpc_id: v } }
        return
      end
    covered_vpcs = Array(resp.vpc_endpoints).map(&:vpc_id)
    vpc_ids.each do |v|
      next if covered_vpcs.include?(v)
      @vpcs_without_appstream_endpoint << { region: region, vpc_id: v }
    end
  end
end
