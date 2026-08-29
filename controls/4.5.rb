# encoding: UTF-8

control 'C-4.5' do
  title 'Ensure new users can only be invited from allowed domains.'
  desc  "
    Users that are allowed access to shared files or folders in WorkDocs should be limited to specific domains.

    To control who should be allowed to join your WorkDocs site, users should be limited on who they can invite sharing files or folders with new people from the specified domains.
  "
  desc  'rationale', "
    Users that are allowed access to shared files or folders in WorkDocs should be limited to specific domains.

    To control who should be allowed to join your WorkDocs site, users should be limited on who they can invite sharing files or folders with new people from the specified domains.
  "
  desc  'check', "
    Perform the steps to confirm WorkDocs file and sharing folders is controlled by specified domains.

    From the WorkDocs Admin control panel

    1. Log in to WorkDocs as an Administrator

    2. Click `Security`

    3. Under - `Invite settings`

    4. Confirm that only 

    `Users can invite new people from a few specific domains by sharing files or folders with them`

    5. Confirm the listed `Domains` is accurate.

    If the setting is not set to \"Users can invite new people from a few specific domains by sharing files or folders with them\" or the domains listed is not accurate refer to the remediation below.
  "
  desc  'fix', "
    Perform the steps to set WorkDocs file and sharing folders to be controlled by specified domains.

    From the WorkDocs Admin control panel

    1. Log in to WorkDocs as an Administrator

    2. Click `Security`

    3. Under - `Invite settings`

    4. Select  

    `Users can invite new people from a few specific domains by sharing files or folders with them`

    5. Add in or edit the listed allowed Domains.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '4.5'
  tag cis_rid:               '4.5'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0405r1_rule'
  tag cis_version:           '1.2.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('workdocs')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("WORKDOCS out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  uri          = input('c_4_5_attestation_uri', value: attestation_uri(:boundary, 'C-4.5'))
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (\"allowed domain\" for new-user invitations is consumer-policy-specific (which corporate domains are partner-approved). Operators attest from their identity-domain inventory.) [Lift to Pass-with-evidence: set boundary_docs_base / c_4_5_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-4.5 governance attestation (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current within #{max_age_days}d") { expect(doc.current?).to eq(true) }
    end
  end
end