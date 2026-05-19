# encoding: UTF-8

control 'C-2.14' do
  title 'Ensure WorkSpaces that are not being utilized are removed.'
  desc  "
    Identify and remove any WorkSpace instances available within your AWS account that are not being utilized.

    An AWS WorkSpaces instance is considered unused if has 0 (zero) known user connections registered within the past 30 days.
  "
  desc  'rationale', "
    Identify and remove any WorkSpace instances available within your AWS account that are not being utilized.

    An AWS WorkSpaces instance is considered unused if has 0 (zero) known user connections registered within the past 30 days.
  "
  desc  'check', "
    Perform the following to ensure WorkSpaces not being utilized have been removed. 

    From the Console:

    1. Log in to the WorkSpaces dashboard at `https://console.aws.amazon.com/workspaces/`.

    2. In the left panel click `WorkSpaces`

    3. Choose the WorkSpaces instance that you want to examine.

    4. Click on WorkSpace id link.

    	-Verify the User Last Active attribute value is less than 30 days old

    6. Repeat step 4 to verify the last user login, returned by the User Last Active attribute value, for all WorkSpaces.

    7. Change the AWS region and repeat the audit process for other regions. 

    If the User Last Active was registered more than 30 days ago (e.g. Feb 16, 2017 10:32:54 UTC), the selected WorkSpaces instance is not in use anymore and can be safely removed from your AWS account.  Refer to the remediation procedure below.

    From the Command line:

    1. Run the describe-workspaces command to list the IDs of all WorkSpaces instances available within the selected region:
    ```
    aws workspaces describe-workspaces
    	--region us-east-1
    	--output table
    	--query 'Workspaces[*].WorkspaceId'
    ```
    2. The command should return a table with the requested WorkSpaces IDs:
    ```
    --------------------
    |DescribeWorkspaces|
    +------------------+
    |   ws-7cgsl2k65   |
    |   ws-8d6il5kr3   |
    |   ws-2dtyl1g47   |
    +------------------+
    ```
    3. Run the describe-workspaces-connection-status command using the ID of the WorkSpaces instance in the table output
    ```
    aws workspaces describe-workspaces-connection-status
    	--region us-east-1
    	--workspace-ids ws-7cgsl2k65
    	--query 'WorkspacesConnectionStatus[*].LastKnownUserConnectionTimestamp'
    ```
    4. The command should return the timestamp of the User last active for the selected instance:
    ```
    [
        1489139777.721
    ]
    ```
    5. Run the date command using the timestamp value returned at the previous step to convert it to a human readable date value:
    ```
    date -d @1489139777.721
    ```
    6. Verify the User Last Active attribute value is less than 30 days old
    ```
    Fri Mar 10 09:56:17 UTC 2017
    ```

    If the User last active date returned is more than 30 days ago, the selected WorkSpaces instance is not utilized anymore and can be safely removed from your AWS account.  Refer to the remediation procedure below to remove the WorkSpaces.

    7. Repeat steps 3 - 6 to verify the User Last active date for the other WorkSpaces instances listed in the current region.

    8. Change the AWS region by updating the --region command parameter value and repeat steps no. 1 - 7 to perform the entire audit process for other regions.-
  "
  desc  'fix', "
    Perform the following to remove unused WorkSpaces based on the output collected from the audit procedure 

    From the Console:

    1. Log in to WorkSpaces dashboard at `https://console.aws.amazon.com/workspaces/`.

    2. In the left panel click `WorkSpaces`

    3. Select the WorkSpace ID that you have identified as not being used.
 
    4. Click `Actions`, `Remove WorkSpaces`

    5. Confirm using the Audit that this is the WorkSpaces ID you should remove.

    6. Click `Remove WorkSpaces`

    From the Command line:

    _Note that running this command does not prompt you to confirm that you are removing the correct WorkSpaces ID._

    1. Run terminate-workspaces command using the ID of the WorkSpaces instance from the Audit that you want to delete:
    ```
    aws workspaces terminate-workspaces
    	--region us-east-1
    	--terminate-workspace-requests ws-0cgsl1k23
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-8 a 1', 'MP-6 a']
  tag cci:                   ['CCI-000389', 'CCI-001028']
  tag cis_number:            '2.14'
  tag cis_rid:               '2.14'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0214r1_rule'
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

  describe 'WorkSpaces in non-healthy lifecycle state (CIS 2.14 — orphaned / stuck workspaces)' do
    subject { aws_workspaces_inventory.workspaces_in_unhealthy_state }
    it { should be_empty }
  end
end
