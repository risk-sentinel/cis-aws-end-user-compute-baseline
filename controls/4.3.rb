# encoding: UTF-8

control 'C-4.3' do
  title 'Ensure Workdocs access is limited to a range of allowable IP addresses'
  desc  "
    Access to WorkDocs can be limited to an allowed range of IP addresses.

    Using IP address allow lists, you define and permit access to your WorkDocs site from trusted networks.
  "
  desc  'rationale', "
    Access to WorkDocs can be limited to an allowed range of IP addresses.

    Using IP address allow lists, you define and permit access to your WorkDocs site from trusted networks.
  "
  desc  'check', "
    Perform these steps to review the list of IP addresses allowed to access WorkDocs

    From the Console:

    1. Log into the AWS console.

    2. Navigate to WorkDocs or go to WorkDocs Console at `https://console.aws.amazon.com/zocalo/`

    3. Under My Account, choose `Open admin control panel`.

    4. For IP Allow List, choose `Change`.

    5. Review the IP address ranges and any single IP addresses

    6. Click `Cancel`.

    If the IP address ranges do not match trusted networks refer to the remediation below to create or edit the IP Allow list.
  "
  desc  'fix', "
    Perform the steps below to create or edit the IP Allow list for WorkDocs

    From the Console:

    1. Log into the AWS console.

    2. Navigate to WorkDocs or go to WorkDocs Console at `https://console.aws.amazon.com/zocalo/`

    3. Under My Account, choose `Open admin control panel`.

    4. For IP Allow List, choose `Change`.

    5. For Enter CIDR value, enter the IP address ranges to `allowlist`.  To allow access from a single IP address, specify /32 as the CIDR prefix.

    6. Click `Add`.

    7. Click `Save Changes`.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '4.3'
  tag cis_rid:               '4.3'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0403r1_rule'
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
      its('organizations_without_ip_allowlist') { should be_empty }
    end
  end
end
