# Per-region CloudWatch alarms enumeration filtered by namespace, used
# by the §4 / §5 / §6 / §7 / §9 / §10 monitoring + alerting controls.
# Each engine has CloudWatch metrics under a service-specific namespace
# (`AWS/RDS`, `AWS/DynamoDB`, `AWS/ElastiCache`, `AWS/MemoryDB`,
# `AWS/DocDB`, `AWS/Neptune`, `AWS/Timestream`). A consumer is in
# compliance when at least one CloudWatch alarm exists targeting a
# resource in each enabled service.
#
# This is the "are you actually monitoring this?" check that the
# attestation pattern was previously delegating to a runbook. We
# automate it here so cis-aws-database stands on its own merit (per
# the each-profile-stands-alone feedback memory).
#
# Per-region instantiation. aws-sdk-cloudwatch is bundled in stock
# cinc-auditor.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsCloudwatchAlarmsCoverage < AwsResourceBase
  name "aws_cloudwatch_alarms_coverage"
  desc "CloudWatch alarms coverage for database services (CIS §2.9 (WorkSpaces monitoring))."
  example "
    inv = aws_cloudwatch_alarms_coverage(namespaces: ['AWS/RDS', 'AWS/DocDB'])
    describe inv do
      its('namespaces_without_alarms') { should be_empty }
    end
  "

  attr_reader :alarms, :namespaces, :namespaces_without_alarms

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    @namespaces = Array(opts.delete(:namespaces)).map(&:to_s)
    super(opts)
    validate_parameters
    @alarms = []
    @namespaces_without_alarms = []
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    true
  end

  def to_s
    "CloudWatch alarms coverage (namespaces=#{@namespaces.join(',')})"
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
    @namespaces.each { |ns| classify_namespace(ns) }
  end

  def classify_namespace(namespace)
    found_in_any_region = false
    @regions.each do |region|
      alarms_in_region = list_alarms_in_namespace(region, namespace)
      next if alarms_in_region.empty?
      found_in_any_region = true
      @alarms.concat(alarms_in_region.map { |a| { region: region, namespace: namespace, alarm_name: a.alarm_name, metric_name: a.metric_name } })
    end
    @namespaces_without_alarms << { namespace: namespace } unless found_in_any_region
  end

  def list_alarms_in_namespace(region, namespace)
    alarms = []
    client = ::Aws::CloudWatch::Client.new(region: region)
    next_token = nil
    loop do
      resp =
        begin
          client.describe_alarms(next_token: next_token, alarm_types: ["MetricAlarm"])
        rescue ::Aws::Errors::ServiceError => e
          Inspec::Log.warn("aws_cloudwatch_alarms_coverage: #{region} describe_alarms failed: #{e.message}")
          return alarms
        end
      Array(resp.metric_alarms).each do |a|
        alarms << a if a.namespace.to_s == namespace
      end
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
    alarms
  end
end
