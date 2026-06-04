# encoding: UTF-8
#
# aws_workspaces_admin_iam — VERIFY (don't trust) WorkSpaces administrative IAM
# scope. Built in-profile per `each_profile_stands_alone` (CIS 2.1) — does not
# defer the IAM question to cis-aws-foundations. Scans customer-managed
# (Scope=Local) IAM policies for statements that grant broad WorkSpaces admin
# access — a `workspaces:*` (or `workspaces:Create*`/`Delete*`/`Modify*`) action
# on `Resource: "*"` — which violates least-privilege for the admin boundary.
#
#   describe aws_workspaces_admin_iam do
#     its('policies_with_broad_workspaces_admin') { should be_empty }
#   end
#
# exec_validated: false — list_policies/get_policy_version scanning + statement
# matching not yet verified against a live account; validate before relying on a FAIL.

class AwsWorkspacesAdminIam < AwsResourceBase
  name "aws_workspaces_admin_iam"
  desc "Customer-managed IAM policies granting broad workspaces:* admin on Resource:*."
  example "
    describe aws_workspaces_admin_iam do
      its('policies_with_broad_workspaces_admin') { should be_empty }
    end
  "

  ADMIN_RE = /\Aworkspaces:(\*|Create|Delete|Modify|Terminate|Reboot|Rebuild|Restore|Start|Stop|Update|Register|Deregister|Associate|Disassociate|Authorize|Revoke|Import|Copy)/i

  attr_reader :policies_with_broad_workspaces_admin

  def initialize(opts = {})
    super(opts)
    @policies_with_broad_workspaces_admin = []
    catch_aws_errors do
      require "json"
      require "cgi"
      iam = @aws.iam_client
      marker = nil
      loop do
        resp = iam.list_policies(scope: "Local", only_attached: false, marker: marker)
        Array(resp.policies).each do |p|
          ver = iam.get_policy_version(policy_arn: p.arn, version_id: p.default_version_id)
          doc = JSON.parse(CGI.unescape(ver.policy_version.document.to_s))
          @policies_with_broad_workspaces_admin << p.policy_name if broad_admin?(doc)
        end
        break unless resp.is_truncated
        marker = resp.marker
      end
    end
  end

  def to_s
    "WorkSpaces admin IAM scope"
  end

  private

  def broad_admin?(policy)
    Array(policy["Statement"]).any? do |st|
      next false unless st["Effect"] == "Allow"
      actions   = Array(st["Action"]).map(&:to_s)
      resources = Array(st["Resource"]).map(&:to_s)
      broad_res = resources.include?("*")
      broad_act = actions.any? { |a| a == "*" || a =~ ADMIN_RE }
      broad_res && broad_act
    end
  end
end
