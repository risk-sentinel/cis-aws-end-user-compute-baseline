# encoding: UTF-8

control 'C-2.3' do
  title 'Ensure WorkSpace volumes are encrypted.'
  desc  "
    Encrypt WorkSpaces root volume (C:drive for Windows and root for Amazon Linux) and user volume (D:drive for Windows and /home for Amazon Linux).

    When you launch a WorkSpace, you can encrypt the root volume and the user volume. This ensures that the data stored at rest for WorkSpaces is encrypted.
  "
  desc  'rationale', "
    Encrypt WorkSpaces root volume (C:drive for Windows and root for Amazon Linux) and user volume (D:drive for Windows and /home for Amazon Linux).

    When you launch a WorkSpace, you can encrypt the root volume and the user volume. This ensures that the data stored at rest for WorkSpaces is encrypted.
  "
  desc  'check', "
    Perform the following steps to confirm that data at rest is encrypted for WorkSpaces

    From the Console:

    1. Login to the WorkSpaces dashboard at `https://console.aws.amazon.com/workspaces/`.

    2. In the left pane click `WorkSpaces` to access the instances listing page.

    3. Check the storage volume(s) encryption status for each Amazon WorkSpaces instance available in the current AWS region

    - It will be listed in the Volume Encryption column

    If the value listed in the Volume Encryption column is Disabled, the selected AWS WorkSpaces instance volumes are not encrypted.

    4. Change the AWS region from the navigation bar and repeat step 3 for all other regions. 

    From the Command line:

    1. Run describe-workspaces command (OSX/Linux/UNIX) using custom query filters to list the IDs of all AWS WorkSpaces instances available within the selected region:
    ```
    aws workspaces describe-workspaces --region us-east-1 --output table --query 'Workspaces[*].WorkspaceId'
    ```
    2. The command output should return a table with the requested WorkSpaces IDs:
    ```
    --------------------
    |DescribeWorkspaces|
    +------------------+
    |   ws-aaabbbccc   |
    |   ws-ccceeefff   |
    +------------------+
    ```
    3. Execute again describe-workspaces command (OSX/Linux/UNIX) using the name of the WorkSpaces instance as identifier and custom query filters to get the encryption status for both root and user storage volumes:
    ```
    aws workspaces describe-workspaces --region us-east-1 --workspace-ids ws-aaabbbccc --query 'Workspaces[*].[RootVolumeEncryptionEnabled,UserVolumeEncryptionEnabled]'
    ```
    4. The command output should return the encryption status (flag) for both root and user instance volumes (true for enabled, false for disabled):
    ```
    [
        [
            false,
            false
        ]
    ]
    ```

    If the returned flag value for both root and user volumes is false (as shown in the output example above), the selected AWS WorkSpaces instance volumes are not encrypted.

    5. Repeat step 3 and 4 to verify the storage volumes encryption status for other AWS WorkSpaces instances provisioned in the current region.

    6. Change the AWS region by updating the --region command parameter value and repeat steps 1 - 5 to perform the audit process for other regions.

    If the selected AWS WorkSpaces instance volumes are not encrypted, refer to the remediation procedure below.
  "
  desc  'fix', "
    Perform the following steps to encrypt WorkSpace volumes

    From the Console:

    1. Login to the WorkSpaces console at `https://console.aws.amazon.com/workspaces/`

    2. Click `Launch WorkSpaces` and complete the first three steps.

    3. For the WorkSpaces Configuration step, do the following:
    ```
       - Select the volumes to encrypt: Root Volume, User Volume, or both volumes.

       - For Encryption Key, select an AWS KMS CMK. The CMK that you select must be symmetric.
    ```
    4. Click `Next Step`.

    5. Click `Launch WorkSpaces`.

    NOTE:
    To encrypt existing AWS WorkSpaces data you must re-create the necessary WorkSpaces instances with the volumes encryption feature enabled as outlined above.

    From the Command line:

    1. Run the `create-workspaces` command 
    ```
    aws workspaces create-workspaces --workspaces DirectoryId=`your_directoryID`, UserName=`user_for_workspace`, BundleId=`bundle_to_build`, VolumeEncryptionKey=`AWS_KMS_customer_master_key_(CMK)`, UserVolumeEncryptionEnabled=`true`, RootVolumeEncryptionEnabled='true', WorkspaceProperties={RunningMode=`AUTO_STOP`, RunningModeAutoStopTimeoutInMinutes=`10`, RootVolumeSizeGib=`root_GB`, UserVolumeSizeGib=`user_GB`, ComputeTypeName=`STANDARD`}
    ```
    2. You will receive output highlighting:
    ```
    - FailedRequests - Will contain information about the WorkSpaces that could not be created, and the command failed
    - PendingRequests - Will contain information about the WorkSpaces that were created and the command was successful.
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag ksi:                   ['KSI-SVC-SIN']
  tag nist_r4:               ['SC-28']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '2.3'
  tag cis_rid:               '2.3'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0203r1_rule'
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

  describe 'WorkSpaces with unencrypted root or user volumes (CIS 2.3)' do
    subject { aws_workspaces_inventory.workspaces_unencrypted_volumes }
    it { should be_empty }
  end
end
