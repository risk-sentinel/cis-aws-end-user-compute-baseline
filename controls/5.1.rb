# encoding: UTF-8

control 'C-5.1' do
  title 'Ensure AppStream is utilizing its own virtual private cloud (VPC)'
  desc  "
    AppStream 2.0 should be configured using a VPC with Private subnets and a NAT Gateway.

    For AppStream 2.0 the public subnet will have direct access to the internet through the NAT gateway. This setup allows the streaming instances in your private subnets to connect to the internet or other AWS services.
  "
  desc  'rationale', "
    AppStream 2.0 should be configured using a VPC with Private subnets and a NAT Gateway.

    For AppStream 2.0 the public subnet will have direct access to the internet through the NAT gateway. This setup allows the streaming instances in your private subnets to connect to the internet or other AWS services.
  "
  desc  'check', "
    Perform the following to determine if a VPC is setup for AppStream 2.0 correctly.

    From Console:

    1. Login to the VPC console at `https://console.aws.amazon.com/vpc/`

    2. In the left pane, click `Your VPCs`

    3. Select the VPC for AppStream 2.0 and take note of the name and the VPC ID

    4. In the left pane, click `Subnets`

    5. Confirm you have 3 subnets labeled and associated with the VPC

         `1 AppStream Public Subnet and 2 AppStream Private Subnets`

    6. Confirm the `AppStream Public Subnet` is configured correctly.

         - Select AppStream Public subnet
    ```
    Description tab - VPC matches `AppStream ID and name`  
    Route Table tab  - verify contains rules
    `-Example` - Destination - 10.0.0.0/20, Target - local
    `-Example` - Destination - 0.0.0.0/0, Target - internet_gateway_ID
    ```

    7. Confirm the `2 AppStream Private Subnets` are configured correctly.

         - Select AppStream Private subnet 1
    ```  
    Description Tab - VPC matches `AppStream ID and name` and note Availability zone 
    Route Table tab - verify contains routes
    `-Example` - Destination - 10.0.0.0/20, Target - local
    `-Example` - Destination - 0.0.0.0/0, Target - nat_gateway_ID
    `-Example- optional` - Destination - S3bucket_enpoint_ID, Target - storage_vpce_ID
    ```

         - Select AppStream Private subnet 2

    ```
    Description Tab - VPC matches `AppStream ID and name` and Availability zone is set to something different than Private subnet 1
    Route Table tab - verify contains routes
    `-Example` - Destination - 10.0.0.0/20, Target - local
    `-Example` - Destination - 0.0.0.0/0, Target - nat_gateway_ID
    `-Example- optional` - Destination - S3bucket_enpoint_ID, Target - storage_vpce_ID
    ```

    If The AppStream VPC, subnets and route tables are not configured correctly refer to the remediation procedure below.
  "
  desc  'fix', "
    Perform the steps below to create a VPC, subnets and routing table for AppStream 2.0

    From the Console

    _Allocate an Elastic IP address_

    1. Login in to the Amazon VPC console at `https://console.aws.amazon.com/vpc/`

    2. In the left pane, click `Elastic IPs`.
 
    3. Click `Allocate new address`.
 
    4. Then click on `Allocate`.
 
    5. Make a note of the Elastic IP address.

    6. Click `Close`.
 
    _Create a New VPC with one public subnet and two private subnet's._

    1. Login to the VPC console at `https://console.aws.amazon.com/vpc/`
 
    2. Click `Launch VPC Wizard`.
 
    3. Choose VPC with Public and Private Subnet's` and then click `Select`.
 
    4. Configure the VPC as follows:
    ```
         - `IPv4 CIDR block` - enter a CIDR block from the private (non-publicly routable) IP address range - example. 10.0.0.0/16.
         - `IPv6 CIDR block` - Accept the default value - No IPv6 CIDR Block
         - `VPC name` enter a name for the VPC (example, AppStream VPC).
         - `Public subnet's IPv4 CIDR` - enter a CIDR block from the private (non-publicly routable) IP address range - ie. 10.0.0.0/24.
         - `Availability Zone` - Accept the default value - No Preference
         - `Public subnet name` - enter a name for the subnet (example, AppStream Public Subnet)
         - `Private subnet's IPv4 CIDR` - enter the CIDR block for the subnet.
         - `Availability Zone` - Accept the default value - No Preference
         - `Private subnet name` - enter a name for the subnet (example, AppStream Private Subnet 1).
         - `Elastic IP Allocation ID` - enter the Elastic IP address that you created.
         - `Service Endpoints` - Accept the default value - Blank
         - `Enable DNS hostnames` - Accept the default value - Yes
         - `Hardware tenancy` - Accept the default value - Default
    ```
    5. Click on Create VPC
    *Note that it takes several minutes to set up your VPC. After the VPC is created, choose OK.
 
    _Create the Second Private subnet to the VPC_
 
    1. In the left pane, choose Subnets.
 
    2. Click Create subnet.
    ```
        - `Name tag` - enter a name for the private subnet (example, AppStream Private subnet 2).
        - `VPC` - select the VPC that you created for AppStream 2.0.
        - `Availability Zone` - select a different one than you are using for AppStream2 Private subnet 1.
        - `IPv4 CIDR block` - enter the CIDR block for the subnet.
    ```
    3. Click Create.
 
    _Verify and Name the Route Tables_
 
    1. In the left pane, choose `Subnets`

    2. Select the public subnet that you created (example, AppStream Public subnet)

    3. On the Route Table tab, click the ID of the route table (example, rtb-12345678).
 
    4. Select the route table. 

    5. Under Name, choose the edit icon (the pencil), enter a name (for example, appstream-public-routetable), then click the check mark to save.

    6. On the Routes tab, confirm one destination and target for local traffic and another destination and target that sends all other traffic to the internet gateway (example, igw-0518a307898725db2).
 
    7. In the left pane, choose Subnets.

    8. Select the first private subnet that you created (example, AppStream Private subnet 1)

    9. On the Route Table tab, click the ID of the route table (example, rtb-12345678).
 
    10. Select the route table. Under Name, choose the edit icon (the pencil), enter a name (for example, appstream-private-routetable1), then click the check mark to save.

    11. On the Routes tab, confirm one destination and target for local traffic and another destination and target that sends all other traffic to the NAT gateway (example, nat-06ea352539b2fddfc).

    12. In the left pane, choose Subnets.

    13. Select the second private subnet that you created (example, AppStream Private subnet 2)

    14. On the Route Table tab, click the ID of the route table (example, rtb-12345678).
 
    15. Select the route table. Under Name, choose the edit icon (the pencil), enter a name (for example, appstream-private-routetable2), then click the check mark to save.

    16. On the Routes tab, confirm one destination and target for local traffic and another destination and target that sends all other traffic to the NAT gateway (example, nat-06ea352539b2fddfc).
  "
  tag severity:              'medium'
  tag nist:                  ['AC-8 a']
  tag cci:                   ['CCI-000051']
  tag cis_number:            '5.1'
  tag cis_rid:               '5.1'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0501r1_rule'
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
    describe 'AppStream fleets must run inside a customer VPC' do
      subject { inventory.fleets_without_vpc_config }
      it { should be_empty }
    end
    describe 'AppStream image-builders must run inside a customer VPC' do
      subject { inventory.image_builders_without_vpc_config }
      it { should be_empty }
    end
  end
end
