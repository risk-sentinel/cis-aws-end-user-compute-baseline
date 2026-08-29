# encoding: UTF-8

control 'C-5.5' do
  title 'Ensure session Idle disconnect timeout is set to 10 minutes or less'
  desc  "
    Idle disconnect timeout in minutes is the amount of time that users can be inactive before they are disconnected from their streaming session and the Disconnect timeout in minutes time begins.

    Users are considered idle when they stop providing keyboard or mouse input during their streaming session. File uploads and downloads, audio in, audio out, and pixels changing do not qualify as user activity.  Once disconnected from their streaming session the Disconnect timeout begins.
  "
  desc  'rationale', "
    Idle disconnect timeout in minutes is the amount of time that users can be inactive before they are disconnected from their streaming session and the Disconnect timeout in minutes time begins.

    Users are considered idle when they stop providing keyboard or mouse input during their streaming session. File uploads and downloads, audio in, audio out, and pixels changing do not qualify as user activity.  Once disconnected from their streaming session the Disconnect timeout begins.
  "
  desc  'check', "
    Perform the following steps to view the Fleet settings in AppStream

    From the Console

    1. Log in to the AppStream 2.0 console at `https://console.aws.amazon.com/appstream2`

    2. In the left pane click on `Fleets`.

    3. Select the link for the fleet name you wish to view.

    4. Scroll to the `Fleet configuration` section and confirm that Idle disconnect timeout is set to `10` minutes or less.

    If Idle disconnect timeout is set to anything greater than 10 minutes refer to the remediation below.
  "
  desc  'fix', "
    Perform the following steps to view the Fleet settings in AppStream

    From the Console

    1. Log in to the AppStream 2.0 console at `https://console.aws.amazon.com/appstream2`

    2. In the left pane click on `Fleets`.

    3. Select the link for the fleet name you wish to view.

    4. Scroll to the `Fleet configuration` section and click `Edit`

    6. Change the Idle disconnect timeout to 5 minutes or less and click `Save changes`
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.5'
  tag cis_rid:               '5.5'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0505r1_rule'
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
      its('fleets_with_excessive_idle_disconnect_timeout') { should be_empty }
    end
  end
end
