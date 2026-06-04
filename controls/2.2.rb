# encoding: UTF-8

control 'C-2.2' do
  title 'Ensure MFA is enabled for WorkSpaces users'
  desc  "
    Multi-Factor Authentication (MFA) adds an extra layer of authentication assurance beyond traditional username and password. With MFA enabled, when a user signs in to Amazon WorkSpaces, they will be prompted for their user name and password as well as for an authentication code from their physical or virtual MFA token. It is recommended that MFA be enabled for all accounts that utilize WorkSpaces.

    Enabling MFA provides increased security to a username and password as it requires the user to have a virtual or physical hardware solution that displays a time-sensitive code.
  "
  desc  'rationale', "
    Multi-Factor Authentication (MFA) adds an extra layer of authentication assurance beyond traditional username and password. With MFA enabled, when a user signs in to Amazon WorkSpaces, they will be prompted for their user name and password as well as for an authentication code from their physical or virtual MFA token. It is recommended that MFA be enabled for all accounts that utilize WorkSpaces.

    Enabling MFA provides increased security to a username and password as it requires the user to have a virtual or physical hardware solution that displays a time-sensitive code.
  "
  desc  'check', "
    Preform the following steps to check multi-factor authentication is enabled for WorkSpaces


    From the Console:

    For AWS Managed AD Authenticated Amazon Workspaces Environments:

    1. Identify the IP address of your `RADIUS MFA server` and your `AWS Managed Microsoft AD directory`.

    2. In the AWS Directory Service console navigation pane, select `Directories`.

    3. Choose the directory ID link for your AWS Managed Microsoft AD directory.

    4. On the Directories page, scroll to the `Multi-factor authentication` section.

    5. In the `Multi-factor authentication` section, confirm that it is `enabled` and that Radius Status is completed.

    For Self-Managed AD (with AD Connector) Amazon Workspaces Environments:

    1. Identify the IP address and port of your `RADIUS MFA server` and your `AWS Managed Microsoft AD Connector Identifier`.

    2. In the AWS Workspaces console navigation pane, select `Directories`.

    3. Choose the `directory ID link` for your `AWS Managed Microsoft AD connector`.

    4. On the Directories page, select the `Actions > Update Details`.

    5. In the `Multi-factor authentication` section, confirm that it is enabled and that Radius Status is completed, `Enable Multi-Factor Authentication` is checked and the IP Address of your `Radius MFA server` matches that of the `RADIUS server IP address(es)` field.

    If it is not enabled or the Radius status is in another state refer to the remediation steps below.
  "
  desc  'fix', "
    Perform the steps below to enable multi-factor authentication for WorkSpaces

    From the console:

    For AWS Managed Microsoft AD based Workspaces Environments:

    1. Identify the IP address of your RADIUS MFA server and your AWS Managed Microsoft AD directory.

    2. In the AWS Directory Service console navigation pane, select `Directories`.

    3. Choose the directory ID link for your AWS Managed Microsoft AD directory.

    4. On the Directories page, scroll to the `Multi-factor authentication` section.

    5. In the Multi-factor authentication section, click `Actions`, and then click `Enable`.

    6. On the `Enable multi-factor authentication (MFA)` page, provide the following values:

    - Display label - Provide a label name.
 
    - RADIUS server DNS name or IP addresses
    Note - AWS Directory Service does not support RADIUS Challenge/Response authentication.

    - Port - default 1812

    - Shared secret code
 
    - Confirm shared secret code
 
    - Protocol - MS-CHAPv2
 
    - Server timeout (in seconds) - 20
 
    - Max RADIUS request retries - 3
 
    * Multi-factor authentication is available when the RADIUS Status changes to Enabled.

    7. Click `Enable`.

    For AD Connector based Workspaces Environments:

    1. Identify the IP address and port of your `RADIUS MFA server` and, your `AWS Managed Microsoft AD Connector Identifier`.

    2. In the AWS Workspaces console navigation pane, select `Directories`.

    3. Choose the `directory ID link` for your `AWS Managed Microsoft AD directory connector`.

    4. On the Directories page, scroll to the `Multi-factor authentication` section and select `Edit`.

    5. In the Multi-factor authentication section, select `Enable Multi-factor authentication`.

    6. On the Multi-Factor Authentication section, provide the following values: 

    - RADIUS server DNS name (s) or IP address (s)

    - Port - default 1812 

    - Shared secret code 

    - Confirm shared secret code 

    - Protocol - MS-CHAPv2 

    - Server timeout (in seconds) - 20

    - Max RADIUS request retries - 3

    * Multi-factor authentication is available when the RADIUS Status changes to Enabled.
    
    7. Click `Save`
  "
  tag severity:              'medium'
  tag nist:                  ['IA-2 (2)', 'SI-2 a']
  tag cci:                   ['CCI-000766', 'CCI-001225']
  tag cis_number:            '2.2'
  tag cis_rid:               '2.2'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0202r1_rule'
  tag cis_version:           '1.2.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('workspaces')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("WORKSPACES out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  # VERIFY-don't-trust (Phase C): radius_settings IS exposed by aws_workspaces_inventory
  # (the prior "not exposed" rationale was wrong). When the consumer's MFA model is RADIUS
  # (workspaces_require_radius_mfa: true), assert every directory has a RADIUS server wired
  # rather than trusting an attestation. AD-native MFA (Managed Microsoft AD) is genuinely
  # not WorkSpaces-API-visible -> attestation floor (justified in the coverage matrix).
  inv = aws_workspaces_inventory
  if input('workspaces_require_radius_mfa', value: false) && inv.connection_error.nil?
    describe 'WorkSpaces directories without RADIUS-MFA wired (CIS 2.2)' do
      subject { inv.directories_without_mfa }
      it { should be_empty }
    end
  else
    uri = input('c_2_2_attestation_uri', value: '')
    uri = attestation_uri(:boundary, 'C-2.2') if uri.to_s.empty?
    max_age_days = input('attestation_max_age_days', value: 365)
    if uri.to_s.empty?
      describe 'Requires manual review and attestation' do
        skip "WorkSpaces user MFA via the underlying directory (Simple AD / AD Connector / Managed Microsoft AD). Set workspaces_require_radius_mfa: true to VERIFY radius_settings directly; AD-native MFA is not WorkSpaces-API-visible -> set boundary_docs_base / c_2_2_attestation_uri, or `saf attest apply`."
      end
    else
      doc = document_attestation(uri, max_age_days: max_age_days)
      describe "C-2.2 governance attestation (#{uri})" do
        it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
        it('exists') { expect(doc.exists?).to eq(true) }
        it("current within #{max_age_days}d") { expect(doc.current?).to eq(true) }
      end
    end
  end
end