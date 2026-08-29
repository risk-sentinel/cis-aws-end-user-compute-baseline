# encoding: UTF-8

control 'C-2.18' do
  title 'Ensure Radius server is using the recommended security protocol'
  desc  "
    The authentication protocol between the Microsoft AD DCs and the RADIUS server supported are PAP, CHAP, MS-CHAPv1, and MS-CHAPv2.

    MS-CHAPv2 provides the strongest security of the options supported.
  "
  desc  'rationale', "
    The authentication protocol between the Microsoft AD DCs and the RADIUS server supported are PAP, CHAP, MS-CHAPv1, and MS-CHAPv2.

    MS-CHAPv2 provides the strongest security of the options supported.
  "
  desc  'check', "
    Perform the steps to check multi-factor authentication using the radius server protocol is set to MS-CHAP v2.

    From the Console:

    For AWS Managed AD based environments;
    
    1. Log in to the Directory Service console at `https://console.aws.amazon.com/directoryservicev2`

    2. In the left pane select `Directories`.

    3. Choose the directory ID link for your AWS Managed Microsoft AD directory.
 
    4. On the Directory details page, select the `Networking & security` tab.

    5. In the Multi-factor authentication section, confirm that the Protocol is set to MS-CHAPv2.

    For directory connector / self-managed AD environments

    1. Log in to the AWS Workspaces console at `https://console.aws.amazon.com/workspaces`

    2. In the left pane select `Directories`.

    3. Select the directory ID link for your AWS Managed Microsoft AD directory.

    4. On the `Directories` page, scroll to the `Multi-factor authentication` section and select `Edit`.

    5. In the Multi-factor authentication section confirm that, in the `Protocol` field `MS-CHAPv2` is selected from the dropdown list.

    If it is not set to `MS-CHAPv2` refer to the remediation steps below.
  "
  desc  'fix', "
    Perform the steps below to set the protocol to MS-CHAPv2 for multi-factor authentication.

    From the console:

    For AWS Managed AD based environments;

    1. Log in to the Directory Service console at `https://console.aws.amazon.com/directoryservicev2`

    2. In the left pane select `Directories`.
 
    3. On the Directory details page, select the `Networking & security` tab.
 
    4. In the Multi-factor authentication section, choose `Actions`, and then choose `Edit`.
 
    5. On the Enable multi-factor authentication (MFA) page change the following value:
 
    6. Protocol - `MS-CHAPv2`
 
    7. Click `Save`.

    For directory connector / self-managed AD environments

    1. Log in to the AWS Workspaces console at `https://console.aws.amazon.com/workspaces`

    2. In the left pane select `Directories`.

    3. Select the directory ID link for your AWS Managed Microsoft AD directory.

    4. On the Directories page, scroll to the `Multi-factor authentication` section and select `Edit`.

    5. In the Multi-factor authentication section modify the protocol using the `dropdown` menu to be `MS-CHAPv2` from the currently selected option.

    6. Click `Save` once settings are as desired.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'RA-5 a']
  tag cci:                   ['CCI-000011', 'CCI-001054']
  tag cis_number:            '2.18'
  tag cis_rid:               '2.18'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0218r1_rule'
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

  describe 'WorkSpaces directories with weak Radius authentication protocol (CIS 2.18 — must be MS-CHAPv2)' do
    subject { aws_workspaces_inventory.directories_with_weak_radius_protocol }
    it { should be_empty }
  end
end
