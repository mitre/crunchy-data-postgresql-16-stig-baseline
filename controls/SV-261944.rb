control 'SV-261944' do
  title 'PostgreSQL must generate audit records when privileges/permissions are modified.'
  desc 'Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.

In an SQL environment, modifying permissions is typically done via the GRANT, REVOKE, and DENY commands.'
  desc 'check', 'As the database administrator, verify pgaudit is enabled by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW shared_preload_libraries"

If the output does not contain pgaudit, this is a finding.

Verify that role is enabled:

$ psql -c "SHOW pgaudit.log"

If the output does not contain role, this is a finding.'
  desc 'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed, the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log='role'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000495-DB-000328'
  tag gid: 'V-261944'
  tag rid: 'SV-261944r1000837_rule'
  tag stig_id: 'CD16-00-010000'
  tag fix_id: 'F-65706r1000836_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW shared_preload_libraries;', [input('pg_db')]) do
    its('output') { should include 'pgaudit' }
  end

  pgaudit_types = ['role']

  pgaudit_types.each do |type|
    describe sql.query('SHOW pgaudit.log;', [input('pg_db')]) do
      its('output') { should include type }
    end
  end
end
