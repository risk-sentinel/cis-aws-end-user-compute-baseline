# encoding: UTF-8

control 'C-2.16' do
  title 'Ensure FIPS Endpoint encryption is enabled for WorkSpaces.'
  desc  "
    To meet a high level of security and comply with different compliance standards, you must use Federal Information Processing Standards (FIPS) endpoint encryption at the directory level with WorkSpaces.

    You must also use an AWS Region that is authorized for the same compliance standard that you are trying to achieve.
  "
  desc  'rationale', "
    To meet a high level of security and comply with different compliance standards, you must use Federal Information Processing Standards (FIPS) endpoint encryption at the directory level with WorkSpaces.

    You must also use an AWS Region that is authorized for the same compliance standard that you are trying to achieve.
  "
  desc  'check', "
    Perform the steps below to determine if FIPS endpoint encryption is enabled.

    From the Console:

    1. Log in to the WorkSpaces console at `https://console.aws.amazon.com/workspaces/`

    2. In the left pane, click `Directories`.

    3. Select the directory id link.

    4. Scroll to the `Endpoint encryption` section.

    5. Endpoint Encryption should read
    ```
    - FIPS 140-2 Validated Mode.
    ```
    If Endpoint Encryption is not listed as FIPS 140-2 Validated Mode refer to the remediation procedure below.
  "
  desc  'fix', "
    Perform the steps below to enable FIPS endpoint encryption at the directory level

    From the Console:

    1. Log in to the WorkSpaces console at `https://console.aws.amazon.com/workspaces/`

    2. In the left pane, click `Directories`.

    3. Verify that the directory does not have any existing WorkSpaces associated with it.

    4. Select the directory id link.

    5. Click Actions, `Update Details`.

    6. Scroll to the `Endpoint encryption` section and select `Edit`

    7. For Endpoint Encryption, choose `FIPS 140-2 Validated Mode`.

    8. Click `Save`.

    You can now create WorkSpaces from this directory that utilize FIPS endpoint encryption modules.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '2.16'
  tag cis_rid:               '2.16'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0216r1_rule'
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

  describe 'WorkSpaces directories without FIPS endpoint encryption enabled (CIS 2.16)' do
    subject { aws_workspaces_inventory.directories_without_fips_endpoint }
    it { should be_empty }
  end
end
