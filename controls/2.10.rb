# encoding: UTF-8

control 'C-2.10' do
  title 'Ensure that patches and updates are performed on the operating system for Workstations'
  desc  "
    In order for Windows updates to occur auto-stop WorkSpaces must be utilized and the default for maintenance mode must be set to enabled.

    Windows Operating systems updates can be a high security vulnerability and normal updates and patches can help eliminate these vulnerabilities.
  "
  desc  'rationale', "
    In order for Windows updates to occur auto-stop WorkSpaces must be utilized and the default for maintenance mode must be set to enabled.

    Windows Operating systems updates can be a high security vulnerability and normal updates and patches can help eliminate these vulnerabilities.
  "
  desc  'check', "
    Perform the steps to check maintenance mode for your WorkSpaces:

    From the Console:

    1. Login to the WorkSpaces console at `https://console.aws.amazon.com/workspaces/`

    2. In the left pane, click `Directories`.

    3. Select your directory id link.

    4. Scroll to the `Maintenance mode` section and ensure maintenance mode is set to `Enabled`.

    If it is set to `Enabled` you are meeting this recommendation.

    If it is set to `Disabled`, refer to the remediation below.

    From the Command line:

    1. Run the workspaces command `describe-workspace-directories`
    ```
    aws workspaces describe-workspace-directories
    ```
    2. Review the output under  \"WorkspaceCreationProperties\" for \"EnableMaintenanceMode\" : true
    ```
    Example output:
          \"WorkspaceCreationProperties\" :
          {
            \"EnableInternetAccess\" : false,
            \"EnableWorkDocs\" : true,
            \"UserEnabledAsLocalAdministrator\" : true
            \"EnableMaintenanceMode\" : true
          },
    ```
    If it is set to `true` you are meeting this recommendation.

    If it is set to `false` or is not listed in the output at all, refer to the remediation below.
  "
  desc  'fix', "
    Perform the following steps to enable maintenance mode

    From the Console:

    1. Login to the WorkSpaces console at `https://console.aws.amazon.com/workspaces/`

    2. In the left pane, click `Directories`.

    3. Select your directory id link.

    4. Scroll to the `Maintenance mode` section and click `Edit`

    5. Select `Enable maintenance mode`.

    6. Click `Save`.

    Note
    If you prefer to manage updates manually or with another tool document usage of that, and choose Disabled.

    From the Command line:

    1. Run the WorkSpaces modify-workspace-creation-property command
    ```
    aws workspaces modify-workspace-creation-property --resource-id --workspace-creation-properties EnableMaintenanceMode=true
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['MA-3 a']
  tag cci:                   ['CCI-000865']
  tag cis_number:            '2.10'
  tag cis_rid:               '2.10'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0210r1_rule'
  tag cis_version:           '1.2.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('workspaces')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("WORKSPACES out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (OS patch and update compliance for WorkSpaces is enforced either by enabling EnableMaintenanceMode on the WorkSpaces directory (AWS-managed maintenance window) or by managing patching via SSM Patch Manager. CIS 2.10 measures the former — see follow-up to auto-detect via aws_workspaces_inventory.directories[*].workspace_creation_properties.enable_maintenance_mode. Operator attests via the directory's maintenance-mode setting in the WorkSpaces console in the meantime.)"
  end
end
