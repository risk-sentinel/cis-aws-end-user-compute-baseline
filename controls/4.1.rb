# encoding: UTF-8

control 'C-4.1' do
  title 'Ensure Administrators of WorkDocs is defined using IAM'
  desc  "
    To allow users to administer Amazon WorkDocs resources, you must create an IAM policy that explicitly grants them the correct permissions.  This policy should then be attached to the group or role defined for this administration.

    WorkDocs Administrators control access and authorization for users of the WorkDocs resources.
  "
  desc  'rationale', "
    To allow users to administer Amazon WorkDocs resources, you must create an IAM policy that explicitly grants them the correct permissions.  This policy should then be attached to the group or role defined for this administration.

    WorkDocs Administrators control access and authorization for users of the WorkDocs resources.
  "
  desc  'check', "
    Perform the following to determine what policies are created:

    From the Console:

    1. Login in and open the IAM console at `https://console.aws.amazon.com/iam/`.

    2. In the left pane click on `Groups`.

    3. Click on the group name that should administer WorkDocs.

    4. Click on Permissions and confirm that the AmazonWorkDocsFullAccess policy is attached.

    5. Click on Users and confirm that the list of names are the users approved to administer WorkDocs.

    6. To confirm that the WorkDocs policy (AmazonWorkDocsFullAccess) for admin control is attached to the correct group.

    From the Command Line:

    1. Run the list-attached-group-policies.
    ```
    aws iam list-attached-group-policies --group-name ```
    2. Confirm that the list of users in that Group is correct
    ```
    aws iam get-group --group-name ```
    If the AWS manage policy or a custom WorkDocs Full Access policy is not attached to the group or the users in the group list is not correct refer to the remediation below.
  "
  desc  'fix', "
    Perform the following to create an IAM group and assign the Amazon WorkDocs Full Access policy to it:

    From the Console:

    1. Log in to the IAM console at `https://console.aws.amazon.com/iam/`.

    2. In the left pane, click `Groups` and then click `Create New Group`.

    3. In the Group Name box, type the name of the group and then click `Next Step`.

    4. In the list of policies, select the check box for `AmazonWorkDocsFullAccess`

    5. Click `Next Step`.

    6. Click `Create Group`

    Perform the following to add a user to a Amazon WorkDocs Full Access group:

    1. Log in to the the IAM console at `https://console.aws.amazon.com/iam/`.

    2. In the left pane, click `Groups`

    3. Select the group you created above

    4. Click `Add Users To Group`

    5. Select the users to be added to the group

    6. Click `Add Users`
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 a', 'AC-11 b', 'AC-2 a', 'AC-2 c']
  tag cci:                   ['CCI-000364', 'CCI-000056', 'CCI-002110', 'CCI-002113']
  tag cis_number:            '4.1'
  tag cis_rid:               '4.1'
  tag cis_benchmark:         'CIS AWS End User Compute Services Benchmark v1.2.0'
  tag cis_rule_id:           'SV-0401r1_rule'
  tag cis_version:           '1.2.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('workdocs')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("WORKDOCS out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (WorkDocs admin posture is a property of the consumer's IAM policy inventory — which IAM identities carry workdocs:* permissions, whether MFA is enforced on those identities. The WorkDocs API does not surface admin-identity data per-site, and AWS announced WorkDocs deprecation 2025-04-25; new consumers should not adopt the service. Operator attests for existing deployments only.)"
  end
end
