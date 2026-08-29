# encoding: UTF-8

control 'C-5.6' do
  title 'Ensure internet access is granted and managed through your VPC'
  desc  "
    Default Internet Access from your fleet streaming instances should remain unchecked.

    When Default Internet Access is enabled, AppStream 2.0 uses the internet gateway in the VPC public subnet to connect to the public internet.  The streaming instances are then assigned public IP addresses that are directly accessible from the internet.

    Internet Access from fleet streaming instances should be controlled using a NAT gateway in the VPC.  When Default Internet Access is not enabled, streaming instances are assigned a private IP address that are not directly accessible from the internet.
  "
  desc  'rationale', "
    Default Internet Access from your fleet streaming instances should remain unchecked.

    When Default Internet Access is enabled, AppStream 2.0 uses the internet gateway in the VPC public subnet to connect to the public internet.  The streaming instances are then assigned public IP addresses that are directly accessible from the internet.

    Internet Access from fleet streaming instances should be controlled using a NAT gateway in the VPC.  When Default Internet Access is not enabled, streaming instances are assigned a private IP address that are not directly accessible from the internet.
  "
  desc  'check', "
    Perform the following steps to view the Fleet settings in AppStream

    From the Console

    1. Log in to the AppStream 2.0 console at `https://console.aws.amazon.com/appstream2`

    2. In the left pane click on `Fleets`.

    3. Select the link for the fleet name you wish to view.

    4. On the `Network details` section confirm that Default Internet Access is set to `Disabled`.

    If Default internet access is not set to disabled refer to the remediation below.
  "
  desc  'fix', "
    Perform the following steps to view the Fleet settings in AppStream

    From the console

    1. Log in to the AppStream 2.0 console at `https://console.aws.amazon.com/appstream2`

    2. In the left pane click on `Fleets`.

    3. Select the link for the fleet name you wish to edit.

    4. Click `Actions`, `Stop`

    5. Scroll to the `Network details` section and click `Edit`

    6. Deselect `Default Internet Access`

    7. Click `Save changes`
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '5.6'
  tag cis_rid:               '5.6'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0506r1_rule'
  tag cis_version:           '1.2.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('appstream')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("APPSTREAM out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  inventory = aws_appstream_inventory(regions: input('scan_regions'))

  if inventory.connection_error
    describe 'AWS AppStream 2.0 inventory' do
      skip "Requires manual review and attestation provided for this control (#{inventory.connection_error})"
    end
  else
    describe inventory do
      its('fleets_using_default_internet_access') { should be_empty }
    end
  end
end
