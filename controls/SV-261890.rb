control 'SV-261890' do
  title 'PostgreSQL must uniquely identify and authenticate organizational users (or processes acting on behalf
	of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals using shared accounts, for detailed accountability of individual activity.'
  desc 'check', 'Review PostgreSQL settings to determine whether organizational users are uniquely identified and authenticated when logging on/connecting to the system.

To list all roles in the database, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "\\du"

If organizational users are not uniquely identified and authenticated, this is a finding.

As the database administrator (shown here as "postgres"), verify the current pg_hba.conf authentication settings:

$ sudo su - postgres
$ cat ${PGDATA?}/pg_hba.conf

If every role does not have unique authentication requirements, this is a finding.

If accounts are determined to be shared, determine if individuals are first individually authenticated. If individuals are not individually authenticated before using the shared account, this is a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

Configure PostgreSQL settings to uniquely identify and authenticate all organizational users who log on/connect to the system.

To create roles, use the following SQL:

CREATE ROLE <role_name> [OPTIONS]

For more information on CREATE ROLE, refer to the official documentation: https://www.postgresql.org/docs/current/static/sql-createrole.html.

For each role created, the database administrator can specify database authentication by editing pg_hba.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/pg_hba.conf

An example pg_hba entry looks like this:

# TYPE DATABASE USER ADDRESS METHOD
host test_db bob 192.168.0.0/16 scram-sha-256

For more information on pg_hba.conf, refer to the official documentation: https://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag gid: 'V-261890'
  tag rid: 'SV-261890r1000675_rule'
  tag stig_id: 'CD16-00-003600'
  tag fix_id: 'F-65652r1000674_fix'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'

  describe sql.query(roles_sql, [input('pg_db')]) do
    its('lines.sort') { should cmp input('pg_users').sort }
  end

  describe postgres_hba_conf(input('pg_hba_conf_file')).where { type == 'local' } do
    its('user.uniq') { should cmp input('pg_owner') }
    its('auth_method.uniq') { should_not include 'trust' }
  end

  describe postgres_hba_conf(input('pg_hba_conf_file')).where { database == 'replication' } do
    its('type.uniq') { should cmp 'host' }
    its('address.uniq.sort') { should cmp input('pg_replicas').sort }
    its('user.uniq') { should cmp 'replication' }
    its('auth_method.uniq') { should be_in input('approved_auth_methods') }
  end

  describe postgres_hba_conf(input('pg_hba_conf_file')).where { type == 'host' } do
    its('auth_method.uniq') { should be_in input('approved_auth_methods') }
  end
end
