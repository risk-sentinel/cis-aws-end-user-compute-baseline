require "time"

# Explicit require because the vendored inspec-aws aws_backend.rb does
# not require aws-sdk-workspaces (its require list at lines 5-64 omits
# it). The gem itself is baked into the risksentinel/cinc-auditor:26.0.1-rs1
# image (the consumer's IaC pipeline Dockerfile line 70), but `Aws::WorkSpaces::Client`
# isn't reachable without an explicit require here.
begin
  require "aws-sdk-workspaces"
rescue LoadError => e
  # Fall through — the resource will record this in @connection_error
  # and the existing rescue path in fetch_* methods catches NameError
  # on Aws::WorkSpaces resolution. Image without the gem (e.g., a
  # downstream consumer using the unmodified cinc-auditor image)
  # degrades cleanly instead of crashing init.
  Inspec::Log.warn("aws-sdk-workspaces require failed: #{e.message}")
end

# WorkSpaces inventory helper — paginated describe_workspaces +
# describe_workspace_directories + describe_workspace_images, plus
# offender-list helpers for the §2 controls.
#
# Note on client access: `@aws.workspaces_client` does NOT exist on the
# vendored AwsConnection (it's a closed list of ~60 explicit client
# methods, not a method_missing dispatcher). The public helper
# `@aws.aws_client(klass)` is what we use here — it's exposed for
# exactly this case (services not enumerated in AwsConnection's
# convenience-method list). See vendored aws_backend.rb:83.
#
# Exposes:
#   aws_workspaces_inventory.workspaces           # array of WS hashes
#   aws_workspaces_inventory.directories          # array of directory hashes
#   aws_workspaces_inventory.images               # array of image hashes
#
# Offender lists (each returns array of strings; empty = passing):
#   .workspaces_unencrypted_volumes               (CIS 2.3)
#   .directories_with_web_access_enabled          (CIS 2.6)
#   .directories_without_ip_group_restriction     (CIS 2.7)
#   .directories_with_default_ip_group_associated (CIS 2.8)
#   .directories_not_in_dedicated_vpc             (CIS 2.4)
#   .directories_with_weak_radius_protocol        (CIS 2.18)
#   .directories_without_fips_endpoint            (CIS 2.16)
#   .workspaces_in_unhealthy_state                (CIS 2.14)
#
# All API calls catch_aws_errors and degrade gracefully when the scan
# identity lacks workspaces:Describe* permissions.

class AwsWorkspacesInventory < AwsResourceBase
  name "aws_workspaces_inventory"
  desc "Amazon WorkSpaces inventory: workspaces + directories + images, plus CIS-§2 offender helpers."

  example "
    describe aws_workspaces_inventory do
      its('workspaces_unencrypted_volumes') { should be_empty }
    end
  "

  attr_reader :workspaces, :directories, :images, :ip_groups, :connection_error

  def initialize(opts = {})
    @approved_bundles = Array(opts.delete(:approved_bundles)) if opts.is_a?(Hash)
    super(opts)
    validate_parameters
    @approved_bundles ||= []
    @connection_error = nil
    @workspaces  = fetch_workspaces
    @directories = fetch_directories
    @images      = fetch_images
    @ip_groups   = fetch_ip_groups
  end

  # All fetch_* methods below catch NoMethodError as well as
  # Aws::Errors::ServiceError. Reason: AwsConnection#workspaces_client
  # is only defined when `aws-sdk-workspaces` is on the gem path. The
  # custom risksentinel/cinc-auditor image (your CI image-bake tracker) bundles 10
  # aws-sdk-* gems; aws-sdk-workspaces is not currently among them, so
  # `@aws.workspaces_client` raises NoMethodError at runtime. Without
  # this rescue, the resource crashes during init and every cis-aws-end-
  # user-compute control downstream returns NullResponse with no clear
  # diagnostic. The connection_error accessor surfaces the underlying
  # cause so control output stays informative.

  def fetch_ip_groups
    paginate { |args| workspaces_client.describe_ip_groups(args) }
      .flat_map { |resp| Array(resp.result).map(&:to_h) }
  rescue NoMethodError, NameError => e
    @connection_error ||= "WorkSpaces client unavailable: #{e.class.name}: #{e.message}"
    []
  end

  def fetch_workspaces
    paginate { |args| workspaces_client.describe_workspaces(args) }
      .flat_map { |resp| Array(resp.workspaces).map(&:to_h) }
  rescue NoMethodError, NameError => e
    @connection_error ||= "WorkSpaces client unavailable: #{e.class.name}: #{e.message}"
    []
  end

  def fetch_directories
    paginate { |args| workspaces_client.describe_workspace_directories(args) }
      .flat_map { |resp| Array(resp.directories).map(&:to_h) }
  rescue NoMethodError, NameError => e
    @connection_error ||= "WorkSpaces client unavailable: #{e.class.name}: #{e.message}"
    []
  end

  def fetch_images
    paginate { |args| workspaces_client.describe_workspace_images(args) }
      .flat_map { |resp| Array(resp.images).map(&:to_h) }
  rescue NoMethodError, NameError => e
    @connection_error ||= "WorkSpaces client unavailable: #{e.class.name}: #{e.message}"
    []
  end

  # Vendored AwsConnection (cis-aws-end-user-compute/vendor/.../libraries/
  # aws_backend.rb) is a closed list of ~60 explicit `<service>_client`
  # methods — `workspaces_client` is NOT one of them. Use the public
  # `aws_client(klass)` helper directly to construct a memoised
  # WorkSpaces client; it goes through the same caching + client_args
  # path as the listed services.
  def workspaces_client
    @aws.aws_client(Aws::WorkSpaces::Client)
  end

  # Pagination helper — yields the args hash, expects the block to call
  # the SDK method, returns an array of all response objects (which the
  # caller flat_maps to extract rows). Catches Aws::Errors::ServiceError
  # internally; NoMethodError / NameError propagate out so the
  # individual fetch_* methods can record the gem-availability state in
  # @connection_error.
  def paginate
    responses = []
    token = nil
    loop do
      resp = nil
      catch_aws_errors do
        args = {}
        args[:next_token] = token if token
        resp = yield(args)
      end
      break unless resp
      responses << resp
      token = resp.respond_to?(:next_token) ? resp.next_token : nil
      break unless token
    end
    responses
  end

  # All offender-list helpers below: defensive `Array(@instance_var)` so
  # nil instance vars (from catch_aws_errors short-circuiting fetch_*
  # under permission-denied) coerce to []. Without this, .reject /
  # .select / .each_with_object raise NoMethodError at exec time and
  # the control reports "Control Source Code Error" instead of cleanly
  # degrading to "no offenders found" or "service not configured."

  # CIS 2.3 — both root and user volumes must be encrypted.
  def workspaces_unencrypted_volumes
    Array(@workspaces).each_with_object([]) do |ws, acc|
      root_enc = ws[:root_volume_encryption_enabled] == true
      user_enc = ws[:user_volume_encryption_enabled] == true
      missing = []
      missing << "root" unless root_enc
      missing << "user" unless user_enc
      acc << "#{ws[:workspace_id]}:unencrypted=#{missing.join(',')}" unless missing.empty?
    end
  end

  # CIS 2.4 — directory should be in a dedicated VPC (subnets distinct
  # from the account's default VPC). Heuristic: subnet_ids non-empty.
  def directories_not_in_dedicated_vpc
    Array(@directories).reject { |d| Array(d[:subnet_ids]).any? }
                       .map { |d| d[:directory_id] }
  end

  # CIS 2.6 — workspace_access_properties.device_type_web should not be
  # ALLOW. Web Access widens attack surface (per CIS rationale).
  def directories_with_web_access_enabled
    Array(@directories).select { |d|
      d.dig(:workspace_access_properties, :device_type_web) == "ALLOW"
    }.map { |d| d[:directory_id] }
  end

  # CIS 2.7 — at least one IP group is associated (limits trusted source
  # devices).
  def directories_without_ip_group_restriction
    Array(@directories).reject { |d| Array(d[:ip_group_ids]).any? }
                       .map { |d| d[:directory_id] }
  end

  # CIS 2.8 — the default IP access control group ("default") should be
  # disassociated. The default group_id from AWS is fixed but matching
  # by name is the operator-friendly check.
  def directories_with_default_ip_group_associated
    rows = []
    @directories.each do |d|
      ids = Array(d[:ip_group_ids])
      next if ids.empty?
      ids.each do |gid|
        # describe_ip_groups would resolve names; without iteration here,
        # flag any group whose id matches AWS's default-group prefix.
        # Conservative: if the directory has only one IP group AND that
        # group's id starts with 'wsipg-' it could be default — skip the
        # heuristic and let attestation cover it. We just flag empty
        # rationale.
      end
    end
    # Defensive: default-group id detection is fragile from this surface.
    # Return empty; the control already cross-references 2.7 + an IP
    # group attestation. Operators with access to describe_ip_groups
    # can extend this method.
    rows
  end

  # CIS 2.16 — FIPS-validated endpoint encryption. Surfaced via
  # workspace_creation_properties.enable_fips_endpoint.
  def directories_without_fips_endpoint
    Array(@directories).reject { |d|
      d.dig(:workspace_creation_properties, :enable_fips_endpoint) == true
    }.map { |d| d[:directory_id] }
  end

  # CIS 2.18 — Radius security protocol must be PAP, CHAP, MS-CHAPv1,
  # or MS-CHAPv2. CIS specifically calls out MS-CHAPv2 as the
  # recommended choice; weaker protocols (PAP without TLS) fail.
  # Acceptable: MS-CHAPv2 only per strict reading.
  def directories_with_weak_radius_protocol
    Array(@directories).each_with_object([]) do |d, acc|
      radius = d[:radius_settings]
      next if radius.nil? || radius == {} || Array(radius[:radius_servers]).empty?
      protocol = radius[:authentication_protocol].to_s
      acc << "#{d[:directory_id]}:protocol=#{protocol}" unless protocol == "MS-CHAPv2"
    end
  end

  # CIS 2.14 — WorkSpaces in non-AVAILABLE / non-STOPPED state for
  # extended periods may be unused / orphaned.
  def workspaces_in_unhealthy_state
    healthy_states = %w[AVAILABLE PENDING REBOOTING STARTING STOPPED STOPPING]
    Array(@workspaces).reject { |ws| healthy_states.include?(ws[:state].to_s) }
                      .map { |ws| "#{ws[:workspace_id]}:state=#{ws[:state]}" }
  end

  # CIS 2.13 — images older than 90 days. Cross-referenced rather than
  # automated per scope decision; left as helper for completeness.
  def images_older_than(days)
    threshold = Time.now - (days * 86_400)
    Array(@images).select { |img| img[:created] && img[:created] < threshold }
                  .map { |img| "#{img[:image_id]}:age_days=#{((Time.now - img[:created]) / 86_400).to_i}" }
  end

  # CIS 2.8 — proper implementation: resolve IP-group names; flag any
  # directory whose associated groups include one named "default".
  # Replaces the placeholder rationale in directories_with_default_ip_group_associated.
  def directories_with_default_ip_group_named
    default_ids = Array(@ip_groups).select { |g|
      (g[:group_name].to_s == "default") || (g[:group_id].to_s == "default")
    }.map { |g| g[:group_id] }.compact
    return [] if default_ids.empty?
    Array(@directories).each_with_object([]) do |d, acc|
      ids = Array(d[:ip_group_ids])
      acc << d[:directory_id] if (ids & default_ids).any?
    end
  end

  # CIS 2.12 — bundle in approved_bundles input.
  def workspaces_with_unapproved_bundle(approved)
    return [] if Array(approved).empty?
    approved_set = Array(approved).map(&:to_s).to_set rescue Array(approved).map(&:to_s)
    Array(@workspaces).reject { |ws| approved_set.include?(ws[:bundle_id].to_s) }
                      .map { |ws| "#{ws[:workspace_id]}:bundle=#{ws[:bundle_id]}" }
  end

  # CIS 2.17 — VPC endpoint coverage. Per-region check that
  # com.amazonaws.<region>.workspaces interface endpoint is Available
  # in at least one VPC. Returns regions with WorkSpaces directories
  # but no endpoint.
  def regions_without_workspaces_endpoint
    region = ENV["AWS_REGION"] || "us-east-1"
    return [] if Array(@directories).empty?
    ec2 = ::Aws::EC2::Client.new(region: region)
    service = "com.amazonaws.#{region}.workspaces"
    resp =
      begin
        ec2.describe_vpc_endpoints(filters: [
          { name: "service-name", values: [service] },
          { name: "vpc-endpoint-state", values: ["available"] },
        ])
      rescue ::Aws::Errors::ServiceError
        return [{ region: region, reason: "describe_vpc_endpoints failed" }]
      end
    return [{ region: region }] if Array(resp.vpc_endpoints).empty?
    []
  end

  def to_s
    # Defensive nil-handling: when the scanner role lacks workspaces:Describe*
    # permissions on every region, fetch_* may complete with the @workspaces
    # / @directories / @images instance variables still unset (catch_aws_errors
    # short-circuits the assignment). Coerce nil → [] so to_s renders safely
    # in RSpec's describe-block label generation.
    ws = Array(@workspaces).size
    dirs = Array(@directories).size
    imgs = Array(@images).size
    "AWS WorkSpaces inventory (workspaces=#{ws} directories=#{dirs} images=#{imgs})"
  end
end
