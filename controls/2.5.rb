# encoding: UTF-8

control 'C-2.5' do
  title 'Ensure WorkSpaces traffic is controlled and routed through a NAT Gateway.'
  desc  "
    A network address translation (NAT) gateway enables instances in a private subnet to connect to the internet or other AWS services, but prevents the internet from initiating a direct connection with those instances.

    WorkSpaces must have access to the internet so that you can install updates to the operating system and deploy applications.
  "
  desc  'rationale', "
    A network address translation (NAT) gateway enables instances in a private subnet to connect to the internet or other AWS services, but prevents the internet from initiating a direct connection with those instances.

    WorkSpaces must have access to the internet so that you can install updates to the operating system and deploy applications.
  "
  desc  'check', "
    Perform the following steps to verify a NAT Gateway is configured and utilized.

    From the Console:

    1. Login to the VPC console at `https://console.aws.amazon.com/vpc/`

    2. In the left pane, click `Route Tables`.

    3. On the Route Table tab.

    4. Select the public route table set for WorkSpaces.

    5. Click the `Subnet Associations` Tab

    6. Confirm that the Subnet ID is set to the WorkSpaces Public subnet.

    7. De-select the public route table and select the WorkSpaces Private route table.

    8. Click the `Subnet Associations` Tab

    9. Confirm that the Subnet ID is set to the 2 WorkSpaces Private subnet.

    If the Route tables aren't set for one route for local traffic and another route that sends all other traffic to the internet gateway for the VPC refer to the remediation procedure below.
  "
  desc  'fix', "
    Perform the following steps to create a NAT gateway

    From the Console:

    1. Login to the VPC console at `https://console.aws.amazon.com/vpc/`

    2. In the left pane, click `NAT Gateways`

    3. Click `Create NAT Gateway`.

    4. For NAT Gateway settings
    ```
    - Name - although optional use something to identify it with WorkSpaces

    - Specify the subnet in which to create the NAT gateway

    - Select the Elastic IP Allocation ID
    ```
    5. Click `Create a NAT Gateway`.

    _The NAT gateway will display in the console and after a few moments, its status will change to Available.

    If the NAT gateway goes to a status of Failed, there was an error during creation._

    After you've created your NAT gateway, you must update your route tables for your private subnets to point internet traffic to the NAT gateway.

    To create a route for a NAT gateway

    1. Log in to the VPC console at `https://console.aws.amazon.com/vpc/`.

    2. In the left pane, Click `Route Tables`.

    3. Select the route table associated with your private subnet.

    4. Click `Routes` tab.

    5. Click `Edit routes`

    6. Click `Add route`

    7. For Edit routes
    ```
    - Destination, enter 0.0.0.0/0.

    - Target, select the ID of your NAT gateway.
    ```
    8. Click `Save routes`
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-4 (5)', 'AC-8 a']
  tag nist_r4:               ['SI-4 (5)']
  tag cci:                   ['CCI-002663', 'CCI-000051']
  tag cis_number:            '2.5'
  tag cis_rid:               '2.5'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0205r1_rule'
  tag cis_version:           '1.2.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('workspaces')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("WORKSPACES out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  # VERIFY-don't-trust + each_profile_stands_alone (Phase C correction): built
  # in-profile, not deferred to another profile. VERIFY is the default; attestation
  # is an explicit opt-out (set c_2_5_attestation_uri) for scanners lacking the IAM/EC2 reads.
  uri = input('c_2_5_attestation_uri', value: '')
  if uri.to_s.empty?
    describe aws_workspaces_egress_routing do
      its('directories_with_public_route') { should be_empty }
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "C-2.5 WorkSpaces egress routing attestation (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end