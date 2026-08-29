# encoding: UTF-8

control 'C-4.8' do
  title 'Ensure any user that has not accessed WorkDocs in 30 days is set to inactive.'
  desc  "
    User accounts that are not actively using the WorkDocs service should be set to inactive after a period of 30 days.

    Inactive accounts may appear to not pose a problem but they can provide unauthorized access to files within WorkDocs.
  "
  desc  'rationale', "
    User accounts that are not actively using the WorkDocs service should be set to inactive after a period of 30 days.

    Inactive accounts may appear to not pose a problem but they can provide unauthorized access to files within WorkDocs.
  "
  desc  'check', "
    Perform the following steps to review list of users

    From the WorkDocs Admin control panel

    1. Log in to WorkDocs as an Administrator

    2. Under `My Account`, choose `Open admin control panel`.

    3. Under `Manage User`s, choose `Download user`.

    4. For Download user, choose `All users`

    5. Review the file to determine if any users have not accessed WorkDocs in the past 30 days.

    If you find any users that have not accessed WorkDocs in the past 30 days refer to the remediation below.
  "
  desc  'fix', "
    Perform the steps below to disable a user's access by changing their status to Inactive.

    From the WorkDocs Admin control panel

    1. Log in to WorkDocs as an Administrator.

    2. Under `My Account`, click `Open admin control panel`.

    3. Under `Manage Users`, choose the pencil icon next to the user's name that needs to be set as inactive.

    4. Choose `Inactive`, and Click Save Changes

    The inactivated user no longer has access to your Amazon WorkDocs site.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 a', 'AC-2 f', 'RA-5 a', 'CM-6 a']
  tag cci:                   ['CCI-002110', 'CCI-000011', 'CCI-001054', 'CCI-000363']
  tag cis_number:            '4.8'
  tag cis_rid:               '4.8'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0408r1_rule'
  tag cis_version:           '1.2.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('workdocs')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("WORKDOCS out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  inventory = aws_workdocs_inventory(
    regions: input('scan_regions'),
    inactive_threshold_days: input('workdocs_inactive_threshold_days'),
  )

  if inventory.connection_error
    describe 'Amazon WorkDocs inventory' do
      skip "Requires manual review and attestation provided for this control (#{inventory.connection_error})"
    end
  else
    describe inventory do
      its('inactive_users') { should be_empty }
    end
  end
end
