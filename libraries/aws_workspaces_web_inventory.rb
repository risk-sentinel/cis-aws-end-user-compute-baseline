# Account-wide enumeration of AWS WorkSpaces Web portals + their User
# Access Logging settings, across regions, for cis-aws-end-user-compute
# C-3.1 (Ensure User Access Logging is enabled).
#
# Per-region client instantiation rather than @aws.aws_client(klass) — the
# class-keyed cache in inspec-aws would serialize every region's call
# through one client (see aws_iam_access_analyzers.rb for the precedent).
#
# Defensive `aws-sdk-workspacesweb` require: the upstream cinc-auditor
# image (7.0.107) does NOT bundle aws-sdk-workspacesweb. The Risk Sentinel
# extended image (filed as your CI image-bake tracker) does. When this library runs
# under the upstream image, the require fails and we surface the failure
# via a `connection_error` accessor so the calling control falls back to
# attestation rationale (per docs/dev/Vendored_Resource_Gaps.md §5).
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsWorkSpacesWebInventory < AwsResourceBase
  name "aws_workspaces_web_inventory"
  desc "WorkSpaces Web portals + User Access Logging coverage."
  example "
    inv = aws_workspaces_web_inventory
    if inv.connection_error
      describe inv do
        skip 'attestation-required: ...'
      end
    else
      describe inv do
        its('portals_without_user_access_logging') { should be_empty }
      end
    end
  "

  attr_reader :portals, :portals_without_user_access_logging, :connection_error

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @portals = []
    @portals_without_user_access_logging = []
    @connection_error = nil
    begin
      require "aws-sdk-workspacesweb"
    rescue LoadError => e
      @connection_error = "aws-sdk-workspacesweb not installed: #{e.message}. Use risksentinel/cinc-auditor extended image (your CI image-bake tracker) or attest separately."
      return
    end
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    @connection_error.nil?
  end

  def to_s
    "AWS WorkSpaces Web inventory"
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
      walk_portals(region)
    end
  rescue ::Aws::Errors::ServiceError => e
    @connection_error = "#{e.class}: #{e.message}"
  end

  def walk_portals(region)
    client = ::Aws::WorkSpacesWeb::Client.new(region: region)
    next_token = nil
    loop do
      resp =
        begin
          client.list_portals(next_token: next_token)
        rescue ::Aws::Errors::ServiceError => e
          Inspec::Log.warn("aws_workspaces_web_inventory: #{region} list_portals failed: #{e.message}")
          return
        end
      Array(resp.portals).each do |p|
        @portals << { region: region, arn: p.portal_arn, status: p.portal_status }
        if p.user_access_logging_settings_arn.nil? || p.user_access_logging_settings_arn.empty?
          @portals_without_user_access_logging << { region: region, arn: p.portal_arn }
        end
      end
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
  end
end
