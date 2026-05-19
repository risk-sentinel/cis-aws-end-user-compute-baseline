# encoding: UTF-8

control 'C-2.4' do
  title 'Ensure WorkSpaces are deployed in their own virtual private cloud (VPC)'
  desc  "
    Amazon WorkSpaces VPC should be created with two private subnets for your WorkSpaces and a NAT gateway in a public subnet.

    The NAT gateway will provide WorkSpaces access to the internet for updates to the operating system and so that applications can be deployed using Amazon WorkSpaces Application Manager if that is applicable for your environment.
  "
  desc  'rationale', "
    Amazon WorkSpaces VPC should be created with two private subnets for your WorkSpaces and a NAT gateway in a public subnet.

    The NAT gateway will provide WorkSpaces access to the internet for updates to the operating system and so that applications can be deployed using Amazon WorkSpaces Application Manager if that is applicable for your environment.
  "
  desc  'check', "
    Perform the following steps to confirm that a VPC exists for WorkSpaces and is configured correctly.

    From the Console:

    1. Login to the VPC console at `https://console.aws.amazon.com/vpc/`

    2. In the left pane, click `Your VPC's`

    3. Select the VPC for WorkSpaces

    4. Confirm the IPv4 settings are using a CIDR block from the private (non-publicly routable) IP address ranges.  For example, 10.0.0.0/16. For more information, see the references below.

    5. Confirm the IPv6 CIDR Block, set to `No`.

    6. Confirm the IPv4 CIDR block for the public subnet (example - WorkSpaces Public Subnet)  

    - Availability Zone, set to `No Preference`.

    7. Confirm the IPv4 CIDR block for the first private subnet (example - WorkSpaces Private Subnet 1)
    ```
    - Availability Zone, set for Amazon WorkSpaces.
	
    - Elastic IP Allocation ID

    - Service endpoints - `Blank`

    - Enable DNS hostnames, set to `Yes`.

    - Hardware tenancy, Default.
    ```
    8. Confirm the IPv4 CIDR block for the first private subnet (example - WorkSpaces Private Subnet 2)
    ```
    - Availability Zone set for Amazon WorkSpaces.
    NOTE-Make sure you select a different Availability Zone from the one you selected for the Workspaces Private Subnet 1
	
    - Elastic IP Allocation ID

    - Service endpoints - Blank

    - Enable DNS hostnames, set to `Yes`.

    - Hardware tenancy, Default.
    ```
    If this is not set as referenced above refer to the remediation procedure below.
  "
  desc  'fix', "
    Perform the following steps to create a VPC for Workspaces

    From the Console:

    _Allocate an Elastic IP Address_

    1. Login in to the VPC console at `https://console.aws.amazon.com/vpc/`

    2. In the left pane, click `Elastic IPs`.

    3. Click `Allocate new address`.

    4. On the Allocate new address page, for iPv4 address pool, click `Amazon pool or Owned by me`

    5. Click `Allocate`.
 
    6. Make a note of the Elastic IP address, click `Close`.
 
    _Create a VPC with one public subnet and two private subnets as follows._

    1. Login in to the VPC console at `https://console.aws.amazon.com/vpc/`
 
    2. In the left pane, click `VPC Dashboard` in the upper-left corner.
 
    3. Click `Launch VPC Wizard`.
 
    4. Click `VPC with Public and Private Subnets`

    5. Click `Select`.
 
    6. Configure the VPC as follows:
    ```
    - For IPv4 CIDR block, enter the CIDR block from the private (non-publicly routable) IP address ranges. - example 10.0.0.0/16.
    - For IPv6 CIDR Block, keep `No IPv6 CIDR Block`.
    - For VPC name, enter a `name for the VPC` (example: WorkspacesVPC) 
    - Public subnet's IPv4 CIDR - enter a CIDR block from the private (non-publicly routable) IP address range - ie. 10.0.0.0/24.
    - For Availability Zone, keep `No Preference`.
    - For Public subnet name, enter a `name for the subnet` (example: WorkSpaces Public Subnet).
    - For Private subnet's IPv4 CIDR, enter the CIDR block for the subnet.
    - `Availability Zone` - Accept the default value - No Preference
    - For Private subnet name, enter a `name for the subnet` (example: WorkSpaces Private Subnet 1).
    - For Elastic IP Allocation ID, enter the Elastic IP address that you created.
    - For Service endpoints, `do nothing`.
    - For Enable DNS hostnames, keep `Yes`.
    - For Hardware tenancy, keep `Default`.
    ``` 
    7. Click Create VPC. Note that it takes several minutes to set up your VPC. After the VPC is created.

    8. Click `OK`.
 
    _Create a Second Private Subnet_
 
    1. In the left pane, click `Subnets`.

    2. Click `Create Subnet`.
    ```
    - For Name tag, enter a `name for the private subnet` (example: WorkSpaces Private Subnet 2).
    - For VPC, `select the VPC` that you created.
    - For Availability Zone. Make sure you select a different Availability Zone from the one used in WorkSpaces Private Subnet 1.
    - For IPv4 CIDR block, enter the CIDR block for the subnet.
    ``` 
    3.  Click `Create`.
 
    _Verify and Name the Route Tables for Public_
 
    1. In the left pane, click `Subnets`

    2. Click the `public` subnet that you created. (example: WorkSpaces Public Subnet)
 
    3. On the Route Table tab, choose the ID of the route table (example: rtb-12345678).
 
    4. Click the route table.

    5. Under Name, choose the edit icon, `enter a name` (example: workspaces-public-routetable)

    6. Click the check mark to save the name.
 
    7. On the Routes tab, verify that there is one route for local traffic and another route that sends all other traffic to the internet gateway for the VPC.
 
    _Verify and Name the Route Tables for Private_

    1. In the left pane, click `Subnets`

    2. Click the `private subnet 1` that you created. (example: WorkSpaces Private Subnet 1)
 
    3. On the Route Table tab, choose the ID of the route table (example: rtb-12345678).
 
    4. Click the route table.

    5. Under Name, choose the edit icon, `enter a name` (example: workspaces-private-routetable)

    6. Click the check mark to save the name.
 
    7. On the Routes tab, verify that there is one route for local traffic and another route that sends all other traffic to the NAT gateway.

    8. Repeat steps 1-7 under `Verify and Name the Route Tables for Private' for `WorkSpaces Private Subnet 2`
  "
  tag severity:              'medium'
  tag nist:                  ['AC-8 a']
  tag cci:                   ['CCI-000051']
  tag cis_number:            '2.4'
  tag cis_rid:               '2.4'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0204r1_rule'
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

  describe 'WorkSpaces directories not deployed in a dedicated VPC (no subnet_ids attached) (CIS 2.4)' do
    subject { aws_workspaces_inventory.directories_not_in_dedicated_vpc }
    it { should be_empty }
  end
end
