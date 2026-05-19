# encoding: UTF-8

control 'C-2.9' do
  title 'Ensure CloudWatch is set up for WorkSpaces'
  desc  "
    Set up and utilize Amazon CloudWatch Events for successful logins to WorkSpaces.

    Use Cloudwatch to store/archive WorkSpaces login events for future reference, analysis, and action based on the patterns.  Utilize the IP address collected to figure out where users are logged in from, and then build policies to allow access only to files or data from those WorkSpaces that meet company access criteria. With this information you can also use policy controls to block access from unauthorized IP addresses.
  "
  desc  'rationale', "
    Set up and utilize Amazon CloudWatch Events for successful logins to WorkSpaces.

    Use Cloudwatch to store/archive WorkSpaces login events for future reference, analysis, and action based on the patterns.  Utilize the IP address collected to figure out where users are logged in from, and then build policies to allow access only to files or data from those WorkSpaces that meet company access criteria. With this information you can also use policy controls to block access from unauthorized IP addresses.
  "
  desc  'check', "
    Perform the following steps to review the rules for CloudWatch and WorkSpaces Events

    From the Console:

    1. Login to the CloudWatch console at `https://console.aws.amazon.com/cloudwatch/`

    2. In the left pane click `Rules`.

    3. Click `Rules`.

    4. Click on the Rule Name for your WorkSpaces Access Events

    5. Confirm the `Event Pattern`
    ```
    {
      \"source\": [
        \"aws.workspaces\"
      ],
      \"detail-type\": [
        \"WorkSpaces Access\"
      ]
    }
    ```
    6. Confirm Status is `Enabled`

    7. Confirm at least one Target is created for `CloudWatch Log Group`

    If there is no CloudWatch Event created with the rule as outlined above refer to the remediation below.
  "
  desc  'fix', "
    Perform the following steps to create a Rule for CloudWatch WorkSpaces Events

    From the Console:

    1. Login to the CloudWatch console at `https://console.aws.amazon.com/cloudwatch/`

    2. In the left pane click `Rules`.

    3. Click `Create rule`.

    4. For Event Source, do the following:
    ```
    - Click `Event Pattern` and Build event pattern to match events by service (the default).
    ```
    5. For Service Name, click `WorkSpaces`.

    6. For Event Type, click `WorkSpaces Access`.

    7. For Targets, click `Add target`
    ```
    - Click and Change the Lambda Function to `CloudWatch log group`
    ```
    8. For Log Group, enter /aws/events/workspaces_access

    Note - You can add additional targets for other services to act when a WorkSpaces Access event is detected.

    9. Click `Configure details`.

    10. For Rule definition, `enter a name and description`.

    11. Click `Create rule'

    9. Click `Create rule`.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a', 'AU-5 b']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123', 'CCI-000140']
  tag cis_number:            '2.9'
  tag cis_rid:               '2.9'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0209r1_rule'
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

  describe aws_cloudwatch_alarms_coverage(regions: input('scan_regions'), namespaces: ['AWS/WorkSpaces']) do
    its('namespaces_without_alarms') { should be_empty }
  end
end
