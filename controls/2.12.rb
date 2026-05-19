# encoding: UTF-8

control 'C-2.12' do
  title 'Restrict WorkSpaces Bundle options to organization approved versions'
  desc  "
    Limit the existing WorkSpaces bundles that can be utilized and provisioned within your AWS account.

    Limiting the type of AWS WorkSpaces bundle that can be utilized can address internal security and compliance requirements.
  "
  desc  'rationale', "
    Limit the existing WorkSpaces bundles that can be utilized and provisioned within your AWS account.

    Limiting the type of AWS WorkSpaces bundle that can be utilized can address internal security and compliance requirements.
  "
  desc  'check', "
    Perform the following to ensure available workspace bundles are set.

    From the Console:

    1. Login to the WorkSpaces dashboard at `https://console.aws.amazon.com/workspaces/`.

    2. In the left pane click `WorkSpaces` to access the instances listing page.

    3. Check the bundle type value for each Amazon WorkSpaces instance available in the current AWS region, listed in Bundle column, e.g.

    4. If the value listed in the `Bundle column` is the same for all listed resources, the WorkSpaces instances were launched using the approved bundle type.

    5. Change the AWS region from the navigation bar and repeat step no. 4 for all other regions. 

    If the value listed in the `Bundle column` is not the same for all listed resources, the WorkSpaces instances were not launched using the approved bundle type, refer to the remediation procedure below.

    From the Command line:

    1. Run describe-workspaces command available within the selected region:
    ```
    aws workspaces describe-workspaces
    	--region us-east-1
    	--output table
    	--query 'Workspaces[*].WorkspaceId'
    ```
    2 The command output should return a table with the requested WorkSpaces IDs:
    ```
    --------------------
    |DescribeWorkspaces|
    +------------------+
    |   ws-bbbdddeee   |
    |   ws-aaabbbccc   |
    |   ws-ccceeefff   |
    +------------------+
    ```
    3. Run describe-workspaces command again using the name of the WorkSpaces instance as identifier and custom query filters get the ID of the bundle used by the selected instance:
    ```
    aws workspaces describe-workspaces
    	--region us-east-1
    	--workspace-ids ws-bbbdddeee
    	--query 'Workspaces[*].BundleId'
    ```
    4. The command output should return the requested WorkSpaces bundle ID:
    ``
    [
        \"wsb-ccc333fff\"
    ]
    ``
    5. Run describe-workspace-bundles command to describe the type of the bundle utilized by the selected AWS WorkSpaces instance:
    ```
    aws workspaces describe-workspace-bundles
    	--region us-east-1
    	--bundle-ids wsb-ccc333fff
    	--query 'Bundles[*].ComputeType.Name'
    ```
    6. The command output should return the selected WorkSpaces bundle type:
    ```
    [
        \"PERFORMANCE\"
    ]
    ```
    7. Repeat steps no. 3 - 6 to verify the bundle type used by the rest of the AWS WorkSpaces instances created in the current region.

    8. If the value listed for the `Bundle` is the same for all listed resources, the WorkSpaces instances were launched using the approved bundle type.

    9. Repeat steps 1 - 8 to perform the entire audit process for all other AWS regions.

    If the value listed in the `Bundle` output is not the same for all listed resources, the WorkSpaces instances were not launched using the approved bundle type, refer to the remediation procedure below.
  "
  desc  'fix', "
    Preform the following to limit the bundle type

    Create the required AWS support case:

    From the Console:

    1. Login in to AWS Support Center dashboard at `https://console.aws.amazon.com/support/`.

    2. Click `Create a case`.

    3. For Case details:
    ```
    - Type, choose `Account`

    - Category, choose `Other Account Issues`

    - Subject, \"Limit AWS WorkSpaces instances launch to approved bundle types\".

    - Description textbox, explain that security and compliance requires the need to limit the provisioning of WorkSpaces instances to an approved bundle type.

    - Contact options, leave as default or change as needed.
    ```
    4. Click `Submit`
  "
  tag severity:              'medium'
  tag nist:                  ['CM-11 a', 'CM-7 a']
  tag cci:                   ['CCI-001805', 'CCI-000381']
  tag cis_number:            '2.12'
  tag cis_rid:               '2.12'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0212r1_rule'
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

  approved = Array(input('approved_workspaces_bundles'))
  if approved.empty?
    describe 'WorkSpaces approved bundle versions' do
      skip 'Requires manual review and attestation provided for this control (set `approved_workspaces_bundles` input to a list of approved bundle IDs to enable automated enforcement; operators attest from their bundle-approval register when input is empty)'
    end
  else
    inv = aws_workspaces_inventory
    describe 'WorkSpaces with bundles outside approved_workspaces_bundles allowlist' do
      subject { inv.workspaces_with_unapproved_bundle(approved) }
      it { should be_empty }
    end
  end
end
