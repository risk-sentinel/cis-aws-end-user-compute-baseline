# encoding: UTF-8

control 'C-2.15' do
  title 'Ensure primary interface ports for Workspaces are not open to all inbound traffic.'
  desc  "
    Ensure that the inbound traffic of the primary network interface for all WorkSpaces is not open to all connections 0.0.0.0\\00.

    Attached security groups to the primary elastic network interface (ENI) to manage ports and network communication should not be open to all communication.  They should be restricted to what is required by WorkSpaces, the Organization and other services.
  "
  desc  'rationale', "
    Ensure that the inbound traffic of the primary network interface for all WorkSpaces is not open to all connections 0.0.0.0\\00.

    Attached security groups to the primary elastic network interface (ENI) to manage ports and network communication should not be open to all communication.  They should be restricted to what is required by WorkSpaces, the Organization and other services.
  "
  desc  'check', "
    Perform the steps below to confirm security groups are configured correctly

    From the console:

    1. Login to the VPC console at `https://console.aws.amazon.com/vpc/`

    2. In the left pane, click `Your VPCs`

    3. Note the VPC Id for WorkSpaces

    4. In the left pane, click `Security Groups`

    5. In the `Filter security groups` enter the name of the WorkSpaces VPC

    6. Select the WorkSpaces Security Group

    7. Click on Inbound rules

    8. Confirm that there is no rule for All traffic, All, All, 0.0.0.0/0, -

    If there is a rule for Inbound traffic that is open to all traffic and all ip addresses refer to the remediation below.
  "
  desc  'fix', "
    Perform the steps below to remove Inbound rule that allows all traffic from all IP addresses.

    From the console:

    1. Login to the VPC console at `https://console.aws.amazon.com/vpc/`

    2. In the left pane, click `Your VPCs`

    3. Note the VPC Id for WorkSpaces

    4. In the left pane, click `Security Groups`

    5. In the `Filter security groups` enter the name of the WorkSpaces VPC

    6. Select the WorkSpaces Security Group

    7. Click on `Inbound rules`

    8. Click on `Edit inbound rules`

    9. Click on `Delete` for the rule that shows
    ```
    -All traffic, All, All, 0.0.0.0/0, -
    ```
    10. Click on Save rules

    Note - Make sure you have all the required ports add to Inbound rules as listed in the WorkSpaces documentation outlined in the references so that connectivity to WorkSpaces is not impacted.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'SC-7 a', 'PM-5', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-001097', 'CCI-000207', 'CCI-000051']
  tag cis_number:            '2.15'
  tag cis_rid:               '2.15'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0215r1_rule'
  tag cis_version:           '1.2.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('workspaces')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("WORKSPACES out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (WorkSpaces primary-interface ingress rules live on the workspace security group identified by workspace_security_group_id on each directory. Auto-detection requires fetching each directory's workspace_security_group_id and querying aws_security_group ingress rules for 0.0.0.0/0 entries on remote-access ports; tracked as a future enhancement. Operator inspects the directory SG via `aws ec2 describe-security-groups --group-ids <workspace_security_group_id>` in the meantime.)"
  end
end
