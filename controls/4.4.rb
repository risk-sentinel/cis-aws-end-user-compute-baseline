# encoding: UTF-8

control 'C-4.4' do
  title 'Utilize site wide activity feed for monitoring.'
  desc  "
    Admins can view and export the activity feed for an entire WorkDocs site.

    WorkDoc admins should monitor and export activity feeds for the site as record of activity.  These activity reports should be reviewed every month for any abnormalities and rotated every 90 days.
  "
  desc  'rationale', "
    Admins can view and export the activity feed for an entire WorkDocs site.

    WorkDoc admins should monitor and export activity feeds for the site as record of activity.  These activity reports should be reviewed every month for any abnormalities and rotated every 90 days.
  "
  desc  'check', "
    Perform the steps below to view site-wide activity feed

    From the WorkDocs web application:

    1. Click `Activity feed`.

    2. Click Filter, then Click `Site-wide activity`.

    3. Select Activity Type filters and choose `Date Modified` settings as needed, then click `Apply`.

    4. When the filtered activity feed results appear, search by file, folder, or user name to narrow your results. You can also add or remove filters as needed.
  "
  desc  'fix', "
    Perform the following steps to Export site-wide activity feed

    From the WorkDocs web application:

    1. Click `Activity feed`.

    2. Click Filter, then Click `Site-wide activity`.

    3. Select Activity Type filters and choose `Date Modified` settings as needed, then click `Apply`.

    4. When the filtered activity feed results appear, search by file, folder, or user name to narrow your results. You can also add or remove filters as needed.

    5. Click `Export` 

    6. Export the activity feed as a .csv or .json file.  Any filters you applied are reflected in the exported file.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000123']
  tag cis_number:            '4.4'
  tag cis_rid:               '4.4'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0404r1_rule'
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

  uri          = input('c_4_4_attestation_uri', value: attestation_uri(:boundary, 'C-4.4'))
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (WorkDocs activity-feed is a site-level admin console setting. The WorkDocs SDK does not expose a queryable activity-feed-enabled flag; operator attests via the WorkDocs admin console. AWS announced WorkDocs deprecation 2025-04-25; new consumers should not adopt the service.) [Lift to Pass-with-evidence: set boundary_docs_base / c_4_4_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-4.4 governance attestation (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current within #{max_age_days}d") { expect(doc.current?).to eq(true) }
    end
  end
end