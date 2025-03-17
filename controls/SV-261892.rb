control 'SV-261892' do
  title 'If passwords are used for authentication, PostgreSQL must transmit only encrypted representations of
  passwords.'
  desc 'The DOD standard for authentication is DOD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires Authorizing Official (AO) approval.

In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

PostgreSQL passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database.'
  desc 'check', 'Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

As the database administrator (shown here as "postgres"), review the authentication entries in pg_hba.conf:

$ sudo su - postgres
$ cat ${PGDATA?}/pg_hba.conf

If any entries use the auth_method (last column in records) "password" or "md5", this is a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

As the database administrator (shown here as "postgres"), edit pg_hba.conf authentication file and change all entries of "password" to "scram-sha-256":

$ sudo su - postgres
$ vi ${PGDATA?}/pg_hba.conf
host all all .example.com scram-sha-256'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag gid: 'V-261892'
  tag rid: 'SV-261892r1000681_rule'
  tag stig_id: 'CD16-00-003900'
  tag fix_id: 'F-65654r1000680_fix'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']

  describe postgres_hba_conf("#{input('pg_hba_conf_file')}") do
    its('auth_method') { should_not include 'password' }
    its('auth_method') { should_not include 'md5' }
  end
end
