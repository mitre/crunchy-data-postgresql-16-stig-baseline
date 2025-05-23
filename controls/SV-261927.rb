control 'SV-261927' do
  title 'PostgreSQL must require users to reauthenticate when organization-defined circumstances or situations
	require reauthentication.'
  desc 'The DOD standard for authentication of an interactive user is the presentation of a Common Access Card (CAC) or other physical token bearing a valid, current, DOD-issued Public Key Infrastructure (PKI) certificate, coupled with a Personal Identification Number (PIN) to be entered by the user at the beginning of each session and whenever reauthentication is required.

Without reauthentication, users may access resources or perform tasks for which they do not have authorization. 

When applications provide the capability to change security roles or escalate the functional capability of the application, it is critical the user reauthenticate.

In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances:

(i) When authenticators change; 
(ii) When roles change; 
(iii) When security categories of information systems change; 
(iv) When the execution of privileged functions occurs; 
(v) After a fixed period of time; or
(vi) Periodically.

Within the DOD, the minimum circumstances requiring reauthentication are privilege escalation and role changes.'
  desc 'check', "Determine all situations where a user must reauthenticate. Check if the mechanisms that handle such situations use the following SQL:

To make a single user reauthenticate, the following must be present:

SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user='<username>'

To make all users reauthenticate, run the following:

SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user LIKE '%'

If the provided SQL does not force reauthentication, this is a finding."
  desc 'fix', "Modify and/or configure PostgreSQL and related applications and tools so that users are always required to reauthenticate when changing role or escalating privileges.

To make a single user reauthenticate, the following must be present:

SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user='<username>'

To make all users reauthenticate, the following must be present:

SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user LIKE '%'"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000389-DB-000372'
  tag gid: 'V-261927'
  tag rid: 'SV-261927r1000786_rule'
  tag stig_id: 'CD16-00-008100'
  tag fix_id: 'F-65689r1000785_fix'
  tag cci: ['CCI-002038', 'CCI-004895']
  tag nist: ['IA-11', 'SC-11 b']

  describe 'Determine all situations where a user must re-authenticate' do
    skip 'If the provided SQL queries do not force re-authentication, this is a finding.'
  end
end
