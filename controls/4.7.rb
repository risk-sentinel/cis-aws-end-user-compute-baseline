# encoding: UTF-8

control 'C-4.7' do
  title 'Ensure publicly shareable links is not allowed in WorkDocs'
  desc  "
    The organization should not allow publicly shareable links for WorkDocs.

    If a user can create and send a publicly shareable links allowing a file to be viewed by people outside of the organization it could potentially lead to an security or information leak.
  "
  desc  'rationale', "
    The organization should not allow publicly shareable links for WorkDocs.

    If a user can create and send a publicly shareable links allowing a file to be viewed by people outside of the organization it could potentially lead to an security or information leak.
  "
  desc  'check', "
    Perform the steps to confirm publicly shareable links for WorkDocs is not allowed.

    From the WorkDocs Admin control panel

    1. Log in to WorkDocs as an Administrator

    2. Click `Security`

    3. Under - `public share settings`

    4. Confirm that - `No public sharing is selected`.

    If this is not selected choice refer to the remediation below.
  "
  desc  'fix', "
    Perform the steps to set set publicly shareable links for WorkDocs to not allowed.

    From the WorkDocs Admin control panel

    1. Log in to WorkDocs as an Administrator

    2. Click `Security`

    3. Under - `public share settings`

    4. Select - `No public sharing`. - Users cannot send view links to anyone outside the organization.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '4.7'
  tag cis_rid:               '4.7'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0407r1_rule'
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

  inventory = aws_workdocs_inventory(regions: input('scan_regions'))

  if inventory.connection_error
    describe 'Amazon WorkDocs inventory' do
      skip "Requires manual review and attestation provided for this control (#{inventory.connection_error})"
    end
  else
    describe inventory do
      its('organizations_allowing_public_share') { should be_empty }
    end
  end
end
