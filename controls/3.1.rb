# encoding: UTF-8

control 'C-3.1' do
  title 'Ensure User Access Logging is enabled'
  desc  "
    User Access Logging can record the following user events:
    - Session Start - when a WorkSpaces Web sessions begins.
    - Session End - when a WorkSpaces Web session ends.
    - URL Navigation - when a user loads a URL.

    User Access logging can be setup to record user events.

    Logging user activity will assist in event correlation if response to an incident is needed.
  "
  desc  'rationale', "
    User Access Logging can record the following user events:
    - Session Start - when a WorkSpaces Web sessions begins.
    - Session End - when a WorkSpaces Web session ends.
    - URL Navigation - when a user loads a URL.

    User Access logging can be setup to record user events.

    Logging user activity will assist in event correlation if response to an incident is needed.
  "
  desc  'check', "
    From the Console:
	
    1. Log in to the WorkSpaces console at `https://console.aws.amazon.com/workspaces-web/`

    2. In the left pane, click `Web portals`.

    3. Click the link for correspoinding web portal.

    4. Scroll to the `User access logging` section

    5. Verify the `Kinesis data stream arn` is set.

    If no Kinesis data streams are listed are defined then user access logging is not enabled


    From the Command Line:

    1. From the command line run the `list-user-access-logging-settings`
    ```
    aws workspaces-web list-user-access-logging-settings --output table
    ```
    2.  The command should output a table with the listed settings.

    If no settings are defined then user access logging is not enabled

    ```
    ----------------------------------------------------------------------------------------------------------------------------------------------------
    |                                                           ListUserAccessLoggingSettings                                                          |
    +--------------------------------------------------------------------------------------------------------------------------------------------------+
    ||                                                            userAccessLoggingSettings                                                           ||
    |+------------------------------+-----------------------------------------------------------------------------------------------------------------+|
    ||  kinesisStreamArn            |  arn:aws:kinesis:[region]:[account]:stream/[stream]                                                             ||
    ||  userAccessLoggingSettingsArn|  arn:aws:workspaces-web:[region]:[account]:userAccessLoggingSettings/[stream]                                   ||
    |+------------------------------+-----------------------------------------------------------------------------------------------------------------+|
    ```
  "
  desc  'fix', "
    From the Console:
	
    1. Log in to the Amazon Kinesis console at `https://console.aws.amazon.com/kinesis/home`

    2. In the left pane, click `Data Streams` then `Create data stream`.

    3. Enter a name for your data stream.  The name must be prefixed with `amazon-workspaces-web`

    4. Select the desired data stream capacity and click `Create data stream`

    5. Log into the Amazon WorkSpaces console at `https://console.aws.amazon.com/workspaces/v2/home`

    6.  In the left pane click `Web Portals`

    7. Click the link for the web portal you wish to edit.

    8. Click `Edit`

    9. Scroll to `User access logging` and select the Kinesis data stream you created above.

    10.  Click `Save`

    From the Command Line:
    1.  Run the `create-user-access-logging-settings` command 

    ```
    aws workspaces-web create-user-access-logging-settings --kinesis-stream-arn . --output table
    ```
    2.  The output will return a list of settings

    ```
    --------------------------------------------------------------------------------------------------------------------------------------------------
    |                                                         CreateUserAccessLoggingSettings                                                        |
    +------------------------------+-----------------------------------------------------------------------------------------------------------------+
    |  userAccessLoggingSettingsArn|  arn:aws:workspaces-web:[region]:[account]:userAccessLoggingSettings/[guid]                                     |
    +------------------------------+-----------------------------------------------------------------------------------------------------------------+
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '3.1'
  tag cis_rid:               '3.1'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0301r1_rule'
  tag cis_version:           '1.2.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('workspaces_web')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("WORKSPACES_WEB out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  inventory = aws_workspaces_web_inventory(regions: input('scan_regions'))

  if inventory.connection_error
    describe 'AWS WorkSpaces Web inventory' do
      skip "Requires manual review and attestation provided for this control (#{inventory.connection_error})"
    end
  else
    describe inventory do
      its('portals_without_user_access_logging') { should be_empty }
    end
  end
end
