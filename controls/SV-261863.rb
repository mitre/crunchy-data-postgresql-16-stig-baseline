control 'SV-261863' do
  title 'PostgreSQL must be able to generate audit records when privileges/permissions are retrieved.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role
	information. Therefore, it must be possible to configure auditing to do this. PostgreSQLs typically make such
		information available through views or functions.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not
refer to the implicit retrieval of privileges/permissions/role memberships that PostgreSQL continually performs
to determine if any and every action on the database is permitted.'
  desc 'check', %q(Note: The following instructions use the PGLOG environment variable. Refer to supplementary content APPENDIX-I for instructions on configuring PGLOG.

As the database administrator (shown here as "postgres"), check if pgaudit is enabled by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW shared_preload_libraries"

If pgaudit is not found in the results, this is a finding.

As the database administrator (shown here as "postgres"), list all role memberships for the database:

$ sudo su - postgres
$ psql -c "\du"

Verify the query was logged:

$ sudo su - postgres
$ cat ${PGLOG?}/<latest_log>

This should, as an example, return (among other rows):
< 2024-02-01 19:13:38.276 UTC psql postgres postgres [local] 15639 >LOG:  duration: 29.932 ms  statement: SELECT r.rolname, r.rolsuper, r.rolinherit,
          r.rolcreaterole, r.rolcreatedb, r.rolcanlogin,
          r.rolconnlimit, r.rolvaliduntil
        , r.rolreplication
        , r.rolbypassrls
        FROM pg_catalog.pg_roles r
        WHERE r.rolname !~ '^pg_'
        ORDER BY 1;

If audit records are not produced, this is a finding.)
  desc 'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters): 

pgaudit.log_catalog = 'on'
pgaudit.log = 'read'

Note: For this requirement the pgaudit.log must contain 'read' however APPENDIX-C suggests setting pgaudit.log='ddl, role, read, write' to fulfill all requirements.

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag gid: 'V-261863'
  tag rid: 'SV-261863r1000954_rule'
  tag stig_id: 'CD16-00-000700'
  tag fix_id: 'F-65625r1000954_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW shared_preload_libraries;', [input('pg_db')]) do
    its('output') { should include 'pgaudit' }
  end

  if file(input('pg_audit_log_dir')).exist?
    describe sql.query('\\du;', [input('pg_db')]) do
      its('output') { should match // }
    end

    describe command("grep -r \"AUDIT\" #{input('pg_audit_log_dir')}") do
      its('stdout') { should match /^.*pg_catalog.pg_roles.*$/ }
    end
  else
    describe "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter." do
      skip "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter."
    end
  end
end
