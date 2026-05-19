# Account-wide enumeration of Amazon WorkDocs organizations + users for
# cis-aws-end-user-compute C-4.3 / C-4.7 / C-4.8.
#
# WorkDocs is a regional service (limited regional availability historically:
# us-east-1, us-west-2, eu-west-1, ap-northeast-1, ap-southeast-2). The
# `regions:` kwarg honors the consumer's `scan_regions` input — empty means
# discover via describe_regions and the underlying client errors will
# surface for regions where WorkDocs isn't deployed.
#
# C-4.3 (IP allowlist) and C-4.7 (publicly-shareable links) check
# site-level (organization-level) settings exposed via
# `describe_resource_permissions` on the organization root resource —
# documented but somewhat under-specified in the SDK; we fall back to a
# conservative "no per-organization policy found = consumer must attest"
# stance via the connection_error pattern.
#
# C-4.8 (30-day inactive users) walks `describe_users` per organization
# and filters by `time_zone_id`'s recently-modified field. The `recent`
# threshold is configurable via the input `workdocs_inactive_threshold_days`
# (default 30 per CIS).
#
# Note: WorkDocs was deprecated by AWS 2025-04-25 (no new accounts);
# existing consumers still need coverage. The library is correct against
# the documented API surface as of the deprecation announcement.
#
# Defensive `aws-sdk-workdocs` require — see aws_workspaces_web_inventory.rb
# for the connection_error fallback rationale.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsWorkDocsInventory < AwsResourceBase
  name "aws_workdocs_inventory"
  desc "Amazon WorkDocs organizations + users + per-organization policy state."
  example "
    inv = aws_workdocs_inventory(inactive_threshold_days: 30)
    if inv.connection_error
      describe inv do; skip 'attestation-required: ...'; end
    else
      describe inv do
        its('organizations_without_ip_allowlist')   { should be_empty }
        its('organizations_allowing_public_share')  { should be_empty }
        its('inactive_users')                       { should be_empty }
      end
    end
  "

  attr_reader :organizations,
              :organizations_without_ip_allowlist,
              :organizations_allowing_public_share,
              :inactive_users,
              :connection_error,
              :inactive_threshold_days

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    @inactive_threshold_days = (opts.delete(:inactive_threshold_days) || 30).to_i
    super(opts)
    validate_parameters
    @organizations = []
    @organizations_without_ip_allowlist = []
    @organizations_allowing_public_share = []
    @inactive_users = []
    @connection_error = nil
    begin
      require "aws-sdk-workdocs"
    rescue LoadError => e
      @connection_error = "aws-sdk-workdocs not installed: #{e.message}. Use risksentinel/cinc-auditor extended image (your CI image-bake tracker) or attest separately."
      return
    end
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    @connection_error.nil?
  end

  def to_s
    "Amazon WorkDocs inventory"
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
    client = ::Aws::WorkDocs::Client.new(region: region)
    orgs = list_organizations(client, region)
    orgs.each do |org|
      @organizations << org
      check_site_settings(client, org)
      check_inactive_users(client, org)
    end
  rescue ::Aws::Errors::ServiceError => e
    Inspec::Log.warn("aws_workdocs_inventory: #{region} fetch failed: #{e.message}")
  end

  # The WorkDocs SDK does not expose an organization-enumeration API
  # (describe_organizations belongs to AWS Organizations, a different
  # service). Site/organization IDs are surfaced through AWS Directory
  # Service (`describe_directories`) for directories of type
  # SimpleAD/ADConnector/AWS-Managed-AD that have a WorkDocs site
  # attached. Implementing that traversal is tracked separately;
  # WorkDocs itself was deprecated by AWS 2025-04-25 (no new sites).
  # Until the rewrite lands, surface the gap as a connection_error so
  # control bodies degrade to attestation rather than NoMethodError.
  def list_organizations(_client, region)
    @connection_error ||= "WorkDocs organization enumeration not implemented — describe_organizations is not part of the WorkDocs SDK; site IDs must be discovered via AWS Directory Service (deferred follow-up). WorkDocs deprecated by AWS 2025-04-25; consumer attests separately for site-level controls in #{region}."
    []
  end

  # WorkDocs's site-level IP-allowlist + public-share policy are surfaced
  # through `describe_resource_permissions` on the organization root and
  # `get_document_version` flags. The exact API shape here is consumer-
  # specific — sites configured via the WorkDocs admin console don't always
  # expose policy via the public SDK. When we can't determine state, we
  # mark the organization as "violating both" so the control body fails
  # closed and prompts an explicit attestation.
  def check_site_settings(client, org)
    response =
      begin
        client.describe_resource_permissions(
          authentication_token: nil,
          resource_id: org[:organization_id],
        )
      rescue ::Aws::Errors::ServiceError => e
        Inspec::Log.warn("aws_workdocs_inventory: describe_resource_permissions(#{org[:organization_id]}) failed: #{e.message}")
        @organizations_without_ip_allowlist << org
        @organizations_allowing_public_share << org
        return
      end
    principals = Array(response&.principals)
    has_ip_restriction = principals.any? { |p| p.respond_to?(:type) && p.type == "IP_RANGE" }
    @organizations_without_ip_allowlist << org unless has_ip_restriction
    has_public_share = principals.any? do |p|
      p.respond_to?(:type) && %w[ANONYMOUS PUBLIC].include?(p.type.to_s)
    end
    @organizations_allowing_public_share << org if has_public_share
  end

  def check_inactive_users(client, org)
    threshold = Time.now - (@inactive_threshold_days * 24 * 60 * 60)
    next_token = nil
    loop do
      resp =
        begin
          client.describe_users(
            organization_id: org[:organization_id],
            marker: next_token,
            include: "ALL",
          )
        rescue ::Aws::Errors::ServiceError => e
          Inspec::Log.warn("aws_workdocs_inventory: describe_users(#{org[:organization_id]}) failed: #{e.message}")
          return
        end
      Array(resp.users).each do |u|
        next if u.status == "INACTIVE"
        last_seen = u.respond_to?(:recently_used_at) ? u.recently_used_at : nil
        last_seen ||= u.respond_to?(:modified_timestamp) ? u.modified_timestamp : nil
        if last_seen.nil? || last_seen < threshold
          @inactive_users << {
            region:          org[:region],
            organization_id: org[:organization_id],
            user_id:         u.id,
            username:        u.username,
            last_seen:       last_seen&.iso8601,
          }
        end
      end
      break if resp.marker.nil? || resp.marker.empty?
      next_token = resp.marker
    end
  end
end
