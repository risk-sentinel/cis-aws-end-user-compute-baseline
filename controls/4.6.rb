# encoding: UTF-8

control 'C-4.6' do
  title 'Ensure only specific users are allowed to invite external users'
  desc  "
    The organization should only allow administrators the ability to invite external users to the WorkDocs site.

    If anyone can invite a user outside of the organization it could potentially lead to security or information leak.
  "
  desc  'rationale', "
    The organization should only allow administrators the ability to invite external users to the WorkDocs site.

    If anyone can invite a user outside of the organization it could potentially lead to security or information leak.
  "
  desc  'check', "
    Perform the steps to confirm Only Administrators can invite new external users for WorkDocs.

    From the WorkDocs Admin control panel

    1. Log in to WorkDocs as an Administrator

    2. Click `Security`

    3. Under - `external invites`

    4. Confirm that only

    `Only administrators can invite new external users`

    If this is not set to \"Only administrators can invite new external users\" refer to the remediation below.
  "
  desc  'fix', "
    Perform the steps to Set Only Administrators can invite new external users for WorkDocs.

    From the WorkDocs Admin control panel

    1. Log in to WorkDocs as an Administrator

    2. Click `Security`

    3. Under - `external invites`

    4. Select

    `Only administrators can invite new external users`

    `- Only administrators can invite external users to use Amazon WorkDocs.`
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '4.6'
  tag cis_rid:               '4.6'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0406r1_rule'
  tag cis_version:           '1.2.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('workdocs')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("WORKDOCS out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (\"specific users\" allowed to invite externals is consumer-policy-specific (RBAC role assignment within the WorkDocs site). Operators attest from their role-assignment record.)"
  end
end
