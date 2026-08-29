# encoding: UTF-8

control 'C-5.3' do
  title 'Ensure maximum session duration is no longer than 10 hours'
  desc  "
    When creating a fleet for AppStream 2.0 configure the Maximum session duration in minutes to be no greater than 600.

    Having a session duration lasting longer than 10 hours should not be necessary and if running for any malicious reasons provides a greater time for usage than should be allowed.
  "
  desc  'rationale', "
    When creating a fleet for AppStream 2.0 configure the Maximum session duration in minutes to be no greater than 600.

    Having a session duration lasting longer than 10 hours should not be necessary and if running for any malicious reasons provides a greater time for usage than should be allowed.
  "
  desc  'check', "
    Perform the following steps to view the Fleet settings in AppStream

    From the Console

    1. Log in to the AppStream 2.0 console at `https://console.aws.amazon.com/appstream2`

    2. In the left pane click on `Fleets`.

    3. Select the link for the fleet name you wish to view.

    4. On the `Fleet configuration` section confirm that Maximum session duration is set to `600` minutes or less.

    If Maximum session duration is set to anything greater than 600 minutes refer to the remediation below.
  "
  desc  'fix', "
    Perform the following steps to edit the Fleet settings in AppStream

    From the Console

    1. Log in to the AppStream 2.0 console at `https://console.aws.amazon.com/appstream2`

    2. In the left pane click on `Fleets`.

    3. Select the link for the fleet name you wish to edit.

    4. Click `Actions`, `Stop`

    5. Scroll to the `Fleet configuration` section and click `Edit`

    6. Change the Maximum session duration is set to `600` minutes or less and click `Save Changes`

    7. Click `Actions`, `Start`
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.3'
  tag cis_rid:               '5.3'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0503r1_rule'
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

  inv = aws_appstream_inventory(regions: input('scan_regions'))
  if inv.connection_error
    describe 'AWS AppStream 2.0 inventory' do
      skip "Requires manual review and attestation provided for this control (#{inv.connection_error})"
    end
  else
    describe inv do
      its('fleets_with_excessive_session_duration') { should be_empty }
    end
  end
end
