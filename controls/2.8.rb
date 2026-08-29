# encoding: UTF-8

control 'C-2.8' do
  title 'Ensure the default IP access control group is disassociated.'
  desc  "
    The default IP Access Control group allows all traffic.  Once you create and attach an IP Access Control Group the default is disassociated.

    IP Access Control group acts as a virtual firewall for your WorkSpaces allowing you to add your trusted networks.
  "
  desc  'rationale', "
    The default IP Access Control group allows all traffic.  Once you create and attach an IP Access Control Group the default is disassociated.

    IP Access Control group acts as a virtual firewall for your WorkSpaces allowing you to add your trusted networks.
  "
  desc  'check', "
    Perform the following steps to review your Directory

    From the Console:

    1. Login to the WorkSpaces console at `https://console.aws.amazon.com/workspaces/`
 
    2. In the left pane, click `Directories`.

    3. Select your directory id link.

    4. Scroll to the `IP access control groups` section and click `Edit`.
  
    5. Confirm that you have an IP Access Control Group Associated with this Directory.
 
    6. Make note of the `name(s)` of the IP Access Control Group.
 
    7. Next review the IP Access Control Group
 
    8. In the navigation pane, click `IP Access Controls`.
 
    9. Select the name of the `IP Access Control Group(s)` you record from the Directory.
 
    10. For each IP Access Control Group confirm the source IP address or IP address range, and the Description.
 
    If an IP Access Control group doesn't exist follow the remediation below.

    From the Command line:

    Run the `describe-ip-groups` command
    ```
    aws workspaces describe-ip-groups
    ```
    Review the output for the name and the IP Access controls.

    If an IP Access Control group doesn't exist refer to the remediation below.
  "
  desc  'fix', "
    Perform the steps below to create an IP Access control group.

    From the Console.

    1. Login to the WorkSpaces console at `https://console.aws.amazon.com/workspaces/`
 
    2. In the left pane, Click `IP Access Controls`.

    3. Click `Create IP Group`.

    4. In the `Create IP Group` dialog box, enter a name and description for the group.

    5. Click `Create`.

    6. Select the group

    7. Click `Edit`.

    8. For each IP address, click `Add Rule`.

    9. For Source, enter the IP address or IP address range.

    10. For Description, enter a description. 

    When you are done adding rules, 

    11. Click `Save`.

    Next Associate an IP Access Control Group with a Directory

    1. Login to the WorkSpaces console at `https://console.aws.amazon.com/workspaces/`
 
    2. In the left pane, click `Directories`.
 
    3. Select the directory id link.

    4. Scroll to the `IP access control groups` section and click `Edit`.
 
    5. Select the IP access control group and click `Associate`

    _Note* - If you associate an IP access control group that has no rules with a directory, this blocks all access to all WorkSpaces._

    From the command line:

    Run the `create-ip-group` command
    ```
    aws workspaces create-ip-group --group-name name-of-group --user-rules ipRule=ipaddress_list
    ```
    Associate an IP Access Control Group with a Directory

    Run the 'associate-ip-groups' command
    ```
    aws workspaces associate-ip-groups --directory-id directory_ID --group-ids IDs_of_IP_access_ctrl_group
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '2.8'
  tag cis_rid:               '2.8'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0208r1_rule'
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
    its('directories_with_default_ip_group_named') { should be_empty }
  end
end
