# encoding: UTF-8

control 'C-5.7' do
  title 'Ensure Operating system updates are applied to your base image every 30 days.'
  desc  "
    To ensure that your fleet instances have the latest Windows updates installed, we recommend that you install Windows updates on your image builder, create a new image, and then update your fleet with the new image once a month.

    All fleet instances used in user streaming sessions have only the Windows and application updates that were installed on the underlying image when it was created. In addition, any updates made to Windows or to applications on the instance during the streaming session will not persist to future sessions by the same user or other users.
  "
  desc  'rationale', "
    To ensure that your fleet instances have the latest Windows updates installed, we recommend that you install Windows updates on your image builder, create a new image, and then update your fleet with the new image once a month.

    All fleet instances used in user streaming sessions have only the Windows and application updates that were installed on the underlying image when it was created. In addition, any updates made to Windows or to applications on the instance during the streaming session will not persist to future sessions by the same user or other users.
  "
  desc  'check', "
    Perform the following steps to review the Image date.

    From the Console

    1. Log in to the AppStream 2.0 console at `https://console.aws.amazon.com/appstream2`

    2. In the left pane click on `Images`

    3. Select the `Image Builder` tab

    4. Select the link for the Image builder name you wish to view.

    5. In the `Image builder details` tab review the `Created at date` and the `AppStream agent version`.

    If the created at date is over 30 days old refer to the remediation below.
  "
  desc  'fix', "
    Perform the steps below to create an image and update it.

    From the Console

    1. Log in to the AppStream 2.0 console at `https://console.aws.amazon.com/appstream2`

    2. Click `Images` in the left pane, then Click the `Image Builder` tab, and Click `Launch Image Builder`.

    3. Choose a base image. The latest base images released by AWS is recommended and selected by default.

    4. Click `Next`.

    5. Configure `Image Builder`, by doing the following:
    ```
    - Name: Type a unique name identifier for the image builder.
    -Display name (optional): Type a name to display for the image builder (maximum of 100 characters).
    - Tags (optional): Choose Add Tag, and type the key and value for the tag. To add more tags, repeat this step.
    - Instance Type: Select the instance type for the image builder.
    - Network Access Points (Optional): You can create a private link, which is an interface VPC endpoint (interface endpoint), in your virtual private cloud (VPC). To start creating the interface endpoint, select Create PrivateLink.
    - After you create the interface endpoint, you can use it to keep streaming traffic within your VPC.
    - AppStream 2.0 Agent: This section displays only if you are not using the latest version of the agent.
    - If you are not using the latest AppStream 2.0 agent always select the option to launch your image builder with the latest agent.
    - IAM role (Advanced): Use existing or create a new IAM role
    ```
    6. Click `Next`.

    7. Configure Network, do the following:
    ```
    - Leave Default Internet Access unselected.
    - For VPC and Subnet 1, choose a VPC and two subnets in different Availability Zones.
    - For Security group(s), choose up to five security groups to associate with this image builder.
    - For Active Directory Domain (Optional), expand this section to choose the Active Directory configuration and organizational unit in which to place your streaming instance computer objects. Ensure that the selected network access settings enable DNS resolvability and communication with your directory.
    - Choose Review and confirm the details for the image builder.
    - Review the configuration details.
    ```
    Click `Launch`.

    Next Steps

    Install Operating system updates and install, configure and update your applications for streaming, and then create an image by creating a snapshot of the image builder instance.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 a', 'AC-2 a']
  tag cci:                   ['CCI-000364', 'CCI-002110']
  tag cis_number:            '5.7'
  tag cis_rid:               '5.7'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0507r1_rule'
  tag cis_version:           '1.2.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('appstream')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("APPSTREAM out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (AppStream image OS-update cadence — every 30 days per CIS 5.7 — is image-build-pipeline scope. Auto-detection is feasible via aws_appstream_inventory.image_builders[*].created_time (flag any image_builder older than 30 days as an offender); tracked as a future enhancement. Operator attests via their image-bake schedule in the meantime.)"
  end
end
