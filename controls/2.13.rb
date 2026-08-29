# encoding: UTF-8

control 'C-2.13' do
  title 'Ensure Workspaces images are not older than 90 days.'
  desc  "
    WorkSpaces images should not have a creation time stamp over 90 days.

    WorkSpaces images require Operating system patches to be applied and updated and by confirming the creation date is not over 90 days old can help ensure that updates are being applied.
  "
  desc  'rationale', "
    WorkSpaces images should not have a creation time stamp over 90 days.

    WorkSpaces images require Operating system patches to be applied and updated and by confirming the creation date is not over 90 days old can help ensure that updates are being applied.
  "
  desc  'check', "
    Perform the following to determine the age of WorkSpaces images.

    From the Console:

    1. Login to the WorkSpaces dashboard at `https://console.aws.amazon.com/workspaces/`

    2. In the left pane click Images.

    3. Review the Created date and confirm that all images are newer than 90 days.

    If any images are older than 90 days refer to the remediation procedure below.
  "
  desc  'fix', "
    To create a custom image

    From the Console:

    Note - If you are still connected to the WorkSpace, disconnect.

    1. Log in to the WorkSpaces console at `https://console.aws.amazon.com/workspaces/`

    2. In the left pane, choose `WorkSpaces`.

    3. Select the WorkSpace and choose `Actions`, `Create Image`.
    ```
    - A message displays, prompting you to restart your WorkSpace before continuing. Restarting your WorkSpace updates your Amazon WorkSpaces software to the latest version.
    ```
    _Once you have restarted your WorkSpace, repeat Step 4 of this procedure._

    5. Click `Next`.

    6. Enter an image name and a description.

    7. Click `Create Image`. While the image is being created, the status of the WorkSpace is Suspended and the WorkSpace is unavailable.

    In the left pane, click Images. The image is complete when the status of the WorkSpace changes to Available.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-11 a', 'CM-7 a']
  tag nist_r4:               ['CM-11 a', 'CM-7 a']
  tag cci:                   ['CCI-001805', 'CCI-000381']
  tag cis_number:            '2.13'
  tag cis_rid:               '2.13'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0213r1_rule'
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

  describe 'WorkSpaces images older than 90 days (CIS 2.13)' do
    subject { aws_workspaces_inventory.images_older_than(90) }
    it { should be_empty }
  end
end
