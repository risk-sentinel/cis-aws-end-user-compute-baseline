# encoding: UTF-8

control 'C-5.2' do
  title 'Ensure a VPC Endpoint is set for AppStream'
  desc  "
    When you select Using a VPC endpoint, this allows users to only stream from this AppStream 2.0 stack when they have network access to the VPC.

    Virtual Private Cloud (VPC) endpoints allow your users to stream from AppStream 2.0 through your VPC. You can create a VPC endpoint in the VPC of your choosing, then use the endpoint with AppStream 2.0 VPC to maintain the streaming traffic within the VPC.
  "
  desc  'rationale', "
    When you select Using a VPC endpoint, this allows users to only stream from this AppStream 2.0 stack when they have network access to the VPC.

    Virtual Private Cloud (VPC) endpoints allow your users to stream from AppStream 2.0 through your VPC. You can create a VPC endpoint in the VPC of your choosing, then use the endpoint with AppStream 2.0 VPC to maintain the streaming traffic within the VPC.
  "
  desc  'check', "
    Perform the steps to review the interface endpoint set for AppStream 2.0

    From the Console

    1. Log in to the AppStream 2.0 console at `https://console.aws.amazon.com/appstream2`

    2. In the left pane, click `Stacks`, click the link for the stack you wish to view.

    3. Scroll to the `VPC Endpoints` section.

    4. Confirm the Streaming Endpoint listed is the endpoint through which to stream traffic.

    If there is no Streaming endpoint pointing to a specific VPC Endpoint and it is labeled as Internet refer to the remediation below.
  "
  desc  'fix', "
    Perform the following steps to create an interface endpoint

    From the Console:

    1. Log in to the VPC console at `https://console.aws.amazon.com/vpc/`

    2. In the left pane, click `Endpoints`, `Create Endpoint`.

    3. Click `Create Endpoint`.
    ```
    - For Service category, ensure that AWS services is selected.
    - For Service Name, choose com.amazonaws. .appstream.streaming.
    - For VPC, choose a VPC in which to create the interface endpoint.
    - For Subnets, choose the subnets (Availability Zones) in which to create the endpoint network interfaces.
    - Ensure that the Enable Private DNS Name check box is selected.
    - For Security group, select the security group for AppStream
    ```
    4. Click `Create endpoint`.

    _To update a stack to use a new interface endpoint_

    1. Log in to AppStream 2.0 console at `https://console.aws.amazon.com/appstream2`

    2. In the left pane, click `Stacks`, and click the link of the stack name wish to edit.

    3. Scroll to the  `VPC Endpoints`, and then choose `Edit`.

    4. In the Edit VPC Endpoint dialog box, for Streaming Endpoint, choose the endpoint you just created.

    5. Click `Save Changes`.

    Traffic for new streaming sessions will be routed through this endpoint. However, traffic for current streaming sessions continues to be routed through the previously specified endpoint.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-8 a']
  tag nist_r4:               ['AC-8']
  tag cci:                   ['CCI-000051']
  tag cis_number:            '5.2'
  tag cis_rid:               '5.2'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0502r1_rule'
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

  inventory = aws_appstream_inventory(regions: input('scan_regions'))

  if inventory.connection_error
    describe 'AWS AppStream 2.0 inventory' do
      skip "Requires manual review and attestation provided for this control (#{inventory.connection_error})"
    end
  else
    describe inventory do
      its('vpcs_without_appstream_endpoint') { should be_empty }
    end
  end
end
