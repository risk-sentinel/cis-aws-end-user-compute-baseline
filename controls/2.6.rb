# encoding: UTF-8

control 'C-2.6' do
  title 'Ensure Web Access to Workspaces is Disabled'
  desc  "
    WorkSpaces access should be restricted to trusted operating systems and clients

    WorkSpaces access is supported from a variety of clients and operating systems, including HTML5 based browsers. Disabling Web Access prevents access to the Workspace from HTML5 based browsers, ensuring access can only occur from known operating systems.
  "
  desc  'rationale', "
    WorkSpaces access should be restricted to trusted operating systems and clients

    WorkSpaces access is supported from a variety of clients and operating systems, including HTML5 based browsers. Disabling Web Access prevents access to the Workspace from HTML5 based browsers, ensuring access can only occur from known operating systems.
  "
  desc  'check', "
    Perform the following steps to confirm that Web Access is disabled.

    From the Console:

    1. Log in to the WorkSpaces console at `https://console.aws.amazon.com/workspaces/`

    2. In the left pane, click `Directories`.

    3. Select the directory id link you wish to view.

    4. Scroll to the `Other platforms` section.

    5. Confirm that `Web Access` is denied.

    If everything is not configured as above refer to the remediation below.
  "
  desc  'fix', "
    Perform the following steps to disable Web Access.

    From the Console:

    1. Log in to the WorkSpaces console at `https://console.aws.amazon.com/workspaces/`

    2. In the left pane, click `Directories`.

    3. Select the directory id link.

    4. Scroll to the  `Other platforms` section.

    5. Uncheck `Web Access`.

    6. Click `Save`
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-17 (2)']
  tag cci:                   ['CCI-000068']
  tag cis_number:            '2.6'
  tag cis_rid:               '2.6'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0206r1_rule'
  tag cis_version:           '1.2.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('workspaces')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("WORKSPACES out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe 'WorkSpaces directories with Web Access enabled (CIS 2.6 — device_type_web == ALLOW)' do
    subject { aws_workspaces_inventory.directories_with_web_access_enabled }
    it { should be_empty }
  end
end
