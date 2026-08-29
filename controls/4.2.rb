# encoding: UTF-8

control 'C-4.2' do
  title 'Ensure MFA is enabled for WorkDoc users'
  desc  "
    Multi-Factor Authentication (MFA) adds an extra layer of authentication assurance beyond traditional username and password. With MFA enabled, when a user signs in to Amazon WorkDocs, they will be prompted for their user name and password as well as for an authentication code from their MFA token.

    Enabling MFA provides increased security to a user name and password as it requires the user to possess a solution that displays a time-sensitive authentication code.
  "
  desc  'rationale', "
    Multi-Factor Authentication (MFA) adds an extra layer of authentication assurance beyond traditional username and password. With MFA enabled, when a user signs in to Amazon WorkDocs, they will be prompted for their user name and password as well as for an authentication code from their MFA token.

    Enabling MFA provides increased security to a user name and password as it requires the user to possess a solution that displays a time-sensitive authentication code.
  "
  desc  'check', "
    Perform the steps below to confirm MFA setup and configuration.

    From the console:

    1. Log in to the Directory Service console at `https://console.aws.amazon.com/directoryservicev2`

    2. Select `Directories`.

    3. Choose the directory ID link for your AWS Managed Microsoft AD directory.

    4. On the Directory details page, select the `Networking & security tab`.

    5. In the Multi-factor authentication section, Confirm Radius status is set to Enabled.

    6. Open the WorkDocs console at `https://console.aws.amazon.com/zocalo/`

    7. In the Manage Your WorkDocs Sites page, select the desired site and choose `Actions` and `Manage MFA`.

    8. Confirm the values are set correctly.

    Multi-factor authentication is available when the RADIUS Status reads Enabled.

    From the Command line:

    1. Run describe-directories command to list the identifiers of all the Active Directory (AD) Connector directories, available in the selected AWS region:
    ```
    aws ds describe-directories
    	--region us-east-1
    	--output table
    	--query 'DirectoryDescriptions[*].DirectoryId'
    ```
    2. The command output should return a table with the requested resource IDs:
    ```
    ---------------------
    |DescribeDirectories|
    +-------------------+
    |   d-12345abcde    |
    |   d-abcd012345    |
    |   d-aabbcc1234    |
    +-------------------+
    ```
    3. Run describe-directories command using the ID of the AD Connector directory to get the status of the RADIUS MFA server connection:
    ```
    aws ds describe-directories
    	--region us-east-1
    	--directory-ids d-12345abcde
    	--query 'DirectoryDescriptions[*].RadiusStatus'
    ```
    4. The command output should return the requested status information:
    ```
    []
    ```
    5. Repeat steps 3 and 4 to determine the MFA status for other AD Connector directories.

    6. Change the AWS region by updating the --region command parameter value and repeat steps 1 - 5 to perform the audit process for other regions.

    If describe-directories command output returns an empty array, as shown in the example above, there is no RADIUS MFA server configured for the selected AD Directory, therefore the resource does not have Multi-Factor Authentication (MFA) protection enabled.  Refer to the remediation below.
  "
  desc  'fix', "
    Perform the following steps to setup MFA on the server and in WorkDocs.

    From the Console:

    1. Identify the IP address of your RADIUS MFA server and your AWS Managed Microsoft AD directory.

    2. In the AWS Directory Service console navigation pane, select Directories.

    3. Choose the directory ID link for your AWS Managed Microsoft AD directory.

    4. On the Directory details page, select the Networking & security tab.

    5. In the Multi-factor authentication section, choose Actions, and then choose Enable.

    6. On the Enable multi-factor authentication (MFA) page, provide the following values:
    ```
    - Display label - Provide a label name.
 
    - RADIUS server DNS name or IP addresses

    - Port - default 1812

    - Shared secret code
 
    - Confirm shared secret code
    ```

    To enable multi-factor authentication in WorkDocs:

    1. Open WorkDocs console at `https://console.aws.amazon.com/zocalo/`

    2. In the Manage Your WorkDocs Sites page, select the desired site and choose `Actions` and `Manage MFA`.

    3. Enter the following values:
    ```
    - Enable Multi-Factor Authentication

    - Check to enable multi-factor authentication.

    - RADIUS server IP address(es) - The IP addresses of your RADIUS server endpoints

    - Port - The port that your RADIUS server is using for communications. Default RADIUS server port (1812)

    - Shared secret code - The shared secret code that was specified when your RADIUS endpoints were created.

    - Confirm shared secret code

    - Protocol - MS-CHAPv2

    - Server timeout - (in seconds) - 20

    - Max retries - 3
    ```
    4. Choose Enable.

    Multi-factor authentication is available when the RADIUS Status changes to Enabled.

    To enable RADIUS-based MFA protection for your Active Directory (AD) Connector directories, perform the following actions:
    Note: Enabling Multi-Factor authentication for AD Connector directories using the AWS Management Console is not currently supported.

    From the Command line:

    1. Run the enable-radius command:
    ```
    aws ds enable-radius --region us-east-1 --directory-id --radius-settings { \"RadiusServers\": [\"radius. .com\"],\"RadiusPort\": 1812,\"RadiusTimeout\": 20,\"RadiusRetries\": 3,\"SharedSecret\": \"radiusmfa\",\"AuthenticationProtocol\": \"MS-CHAPv2\",\"DisplayLabel\": \"RADIUS Multi-Factor Authentication\",\"UseSameUsername\": true }
    ```
    2. Repeat step 1 for other AD Connectors and the Selected regions.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IA-2 (2)', 'SI-2 a']
  tag ksi:                   ['KSI-CMT-VTD', 'KSI-IAM-APM']
  tag nist_r4:               ['IA-2 (2)', 'SI-2 a']
  tag cci:                   ['CCI-000766', 'CCI-001225']
  tag cis_number:            '4.2'
  tag cis_rid:               '4.2'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0402r1_rule'
  tag cis_version:           '1.2.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('workdocs')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("WORKDOCS out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  uri          = input('c_4_2_attestation_uri', value: attestation_uri(:boundary, 'C-4.2'))
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (WorkDocs user MFA is enforced via the underlying directory (Simple AD / AD Connector / AWS Managed AD), not via a per-site API. Operators attest from the directory MFA configuration.) [Lift to Pass-with-evidence: set boundary_docs_base / c_4_2_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-4.2 governance attestation (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current within #{max_age_days}d") { expect(doc.current?).to eq(true) }
    end
  end
end