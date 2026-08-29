# encoding: UTF-8

control 'C-2.17' do
  title 'Ensure WorkSpaces API requests flow through a VPC Endpoint'
  desc  "
    For any WorkSpaces API requests setup the connection through an interface endpoint in your VPC.

    Utilizing a VPC interface endpoint for WorkSpaces API requests keeps the communication within the AWS network.
  "
  desc  'rationale', "
    For any WorkSpaces API requests setup the connection through an interface endpoint in your VPC.

    Utilizing a VPC interface endpoint for WorkSpaces API requests keeps the communication within the AWS network.
  "
  desc  'check', "
    Perform the steps to determine if WorkSpaces is using a VPC endpoint for API

    From the Command line:

    1. Run the WorkSpaces `describe-workspace-budles' command
    ```
    aws workspaces describe-workspace-bundles --endpoint-url VPC_Endpoint_ID.workspaces.Region.vpce.amazonaws.com 
    ```

    2. Example output of that command:
    ```
    --endpoint-name Endpoint_Name
    --body \"Endpoint_Body\"
    --content-type \"Content_Type\"
     Output_File
    ```

    Confirm the --endpoint-name is equal to the VPC Endpoint that you have created.  If the endpoint name does not match what you created or is blank, refer to the remediation below.
  "
  desc  'fix', "
    Perform the steps below if you need to create a VPC interface endpoint.

    From the Console

    1. Log in to the VPC console at `https://console.aws.amazon.com/vpc/`

    2. In the left pane, click `Endpoints`

    3. Click `Create Endpoint`.

    4. For Service category, ensure that AWS services is selected.

    5. For Service Name, choose Workspaces.  For Type, ensure that it indicates Interface.

    7. Complete the following information.
    ```
    - For VPC, select a VPC in which to create the endpoint.

    - For Subnets, select the subnets (Availability Zones) in which to create the endpoint network interfaces.  Not all Availability Zones may be supported for all AWS services.

    - To enable private DNS for the interface endpoint, for Enable Private DNS Name, select the check box.

    - For Security group, select the security groups to associate with the endpoint network interfaces.
    ```
    8. Click `Create endpoint`

    From the Command line

    1. Run the create-vpc-endpoint command
    ```
    aws ec2 create-vpc-endpoint --vpc-id vpc-ec43eb89 --vpc-endpoint-type Interface --service-name com.amazonaws.us-east-1.elasticloadbalancing --subnet-id subnet-abababab --security-group-id sg-1a2b3c4d
    ```
    In the output that's returned, take note of the DnsName fields. You can use these DNS names to access the AWS service.

    Next perform the steps to add the Endpoint to the WorkSpace image

    From the Command line

    1. Run the copy-workspace-image command including the endpoint url you just created.
    ```
    aws workspaces copy-workspace-image --endpoint-url VPC_Endpoint_ID.workspaces.Region.vpce.amazonaws.com
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-4', 'SI-4 a 1']
  tag ksi:                   ['KSI-CNA-ULN', 'KSI-IAM-ELP', 'KSI-MLA-RVL', 'KSI-PIY-RSD', 'KSI-SVC-EIS', 'KSI-SVC-PRR']
  tag nist_r4:               ['SC-4', 'SI-4 a 1']
  tag cci:                   ['CCI-001090', 'CCI-001253']
  tag cis_number:            '2.17'
  tag cis_rid:               '2.17'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0217r1_rule'
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

  describe aws_workspaces_inventory do
    its('regions_without_workspaces_endpoint') { should be_empty }
  end
end
