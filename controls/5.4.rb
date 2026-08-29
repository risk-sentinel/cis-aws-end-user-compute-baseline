# encoding: UTF-8

control 'C-5.4' do
  title 'Ensure session disconnect timeout is set to 5 minutes or less'
  desc  "
    Disconnect timeout in minutes, is the amount of of time that a streaming session remains active after users disconnect.

    If users try to reconnect to the streaming session after a disconnection or network interruption within the 5 minutes, they are connected to their previous session. Otherwise, they are connected to a new session with a new streaming instance and that instance isn't sitting out there not being used.
  "
  desc  'rationale', "
    Disconnect timeout in minutes, is the amount of of time that a streaming session remains active after users disconnect.

    If users try to reconnect to the streaming session after a disconnection or network interruption within the 5 minutes, they are connected to their previous session. Otherwise, they are connected to a new session with a new streaming instance and that instance isn't sitting out there not being used.
  "
  desc  'check', "
    Perform the following steps to view the Fleet settings in AppStream

    From the Console

    1. Log in to the AppStream 2.0 console at `https://console.aws.amazon.com/appstream2`

    2. In the left pane click on `Fleets`.

    3. Select the link for the fleet name you wish to view.

    4. On the `Fleet configuration` section confirm that Disconnect timeout is set to `5` minutes minutes or less.

    If Disconnect timeout is set to anything greater than 5 minutes refer to the remediation below.
  "
  desc  'fix', "
    Perform the following steps to update the Fleet settings in AppStream

    From the Console

    1. Log in to the AppStream 2.0 console at `https://console.aws.amazon.com/appstream2`

    2. In the left pane click on `Fleets`.

    3. Select the link for the fleet name you wish to edit.

    4. Scroll to the `Fleet configuration` section and click `Edit`

    5. Change the Disconnect timeout to `5` minutes or less.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.4'
  tag cis_rid:               '5.4'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0504r1_rule'
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
      its('fleets_with_excessive_disconnect_timeout') { should be_empty }
    end
  end
end
