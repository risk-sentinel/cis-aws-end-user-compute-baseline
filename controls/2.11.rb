# encoding: UTF-8

control 'C-2.11' do
  title 'Ensure your WorkSpaces image has the appropriate CIS Operating System Benchmark applied'
  desc  "
    Utilize the CIS Benchmark to secure the Operating system image that you are utilizing for your WorkSpaces.

    Securing the Operating system with a CIS Benchmark ensures all systems remain in a secure, compliant and hardened state.
  "
  desc  'rationale', "
    Utilize the CIS Benchmark to secure the Operating system image that you are utilizing for your WorkSpaces.

    Securing the Operating system with a CIS Benchmark ensures all systems remain in a secure, compliant and hardened state.
  "
  desc  'check', "
    Spin up a WorkSpaces instance and run a manual assessment by confirming the CIS Operating System Benchmark recommendations for the applicable operating system are applied.  You can also utilize a 3rd Party Assessment tool that has been certified for the specific CIS Operating System Benchmark to automate this process.
  "
  desc  'fix', "
    Perform the steps below using the downloaded free version of the applicable CIS Operating System Benchmark and manually apply the recommendations for the WorkSpaces instance.  Or Utilize a 3rd Party tool to assess and apply the CIS Operating System Benchmark.

    1. Launch a WorkSpaces Bundle

    2. Access that WorkSpace as an Administrator utilize SSH or RDP.

    3. Apply the Benchmark:
    ```
    - Manually
 
    - Using Active Directory by creating a GPO that matches the Benchmark.
 
    - Or using a Third Party tool that will apply the Benchmark recommendations.
    ```
    4. Assess the WorkSpaces instance manually or with a 3rd Party tool.

    5. Create a workspace bundle that can then be used to launch your production WorkSpaces instances.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 a', 'AC-2 a']
  tag cci:                   ['CCI-000364', 'CCI-002110']
  tag cis_number:            '2.11'
  tag cis_rid:               '2.11'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0211r1_rule'
  tag cis_version:           '1.2.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('workspaces')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("WORKSPACES out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  uri          = input('c_2_11_attestation_uri', value: attestation_uri(:boundary, 'C-2.11'))
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (whether the WorkSpaces base image has the appropriate CIS OS Benchmark applied is image-build-pipeline scope — operators attest from their image-bake artefacts (golden-AMI scan results, not runtime).) [Lift to Pass-with-evidence: set boundary_docs_base / c_2_11_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-2.11 governance attestation (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current within #{max_age_days}d") { expect(doc.current?).to eq(true) }
    end
  end
end