control 'SV-261959' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to execute privileged activities or
	other system-level access occur.'
  desc 'Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

System documentation should include a definition of the functionality considered privileged.

A privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to:
CREATE
ALTER
DROP
GRANT
REVOKE
DENY

Note that it is particularly important to audit and tightly control any action that weakens the implementation of this requirement itself, since the objective is to have a complete audit trail of all administrative activity.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'Note: The following instructions use the PGDATA and PGLOG environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I on PGLOG.

As the database administrator (shown here as "postgres"), create the role "bob" by running the following SQL:

$ sudo su - postgres
$ psql -c "CREATE ROLE bob"

Change the current role to bob and attempt to execute privileged activity:

$ psql -c "CREATE ROLE stig_test SUPERUSER"
$ psql -c "CREATE ROLE stig_test CREATEDB"
$ psql -c "CREATE ROLE stig_test CREATEROLE"
$ psql -c "CREATE ROLE stig_test CREATEUSER"

As the database administrator (shown here as "postgres"), verify that an audit event was produced (use the latest log):

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2024-02-23 20:16:32.396 UTC postgres 56cfa74f.79eb postgres: >ERROR: must be superuser to create superusers
< 2024-02-23 20:16:32.396 UTC postgres 56cfa74f.79eb postgres: >STATEMENT: CREATE ROLE stig_test SUPERUSER;
< 2024-02-23 20:16:48.725 UTC postgres 56cfa74f.79eb postgres: >ERROR: permission denied to create role
< 2024-02-23 20:16:48.725 UTC postgres 56cfa74f.79eb postgres: >STATEMENT: CREATE ROLE stig_test CREATEDB;
< 2024-02-23 20:16:54.365 UTC postgres 56cfa74f.79eb postgres: >ERROR: permission denied to create role
< 2024-02-23 20:16:54.365 UTC postgres 56cfa74f.79eb postgres: >STATEMENT: CREATE ROLE stig_test CREATEROLE;
< 2024-02-23 20:17:05.949 UTC postgres 56cfa74f.79eb postgres: >ERROR: must be superuser to create superusers
< 2024-02-23 20:17:05.949 UTC postgres 56cfa74f.79eb postgres: >STATEMENT: CREATE ROLE stig_test CREATEUSER;

If audit records are not produced, this is a finding.'
  desc 'fix', 'Configure PostgreSQL to produce audit records when unsuccessful attempts to execute privileged SQL.

All denials are logged by default if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000504-DB-000355'
  tag gid: 'V-261959'
  tag rid: 'SV-261959r1000882_rule'
  tag stig_id: 'CD16-00-011500'
  tag fix_id: 'F-65721r1000881_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  if file(input('pg_audit_log_dir')).exist?
    describe sql.query('CREATE ROLE fooaudit; SET ROLE fooaudit; CREATE ROLE fooauditbad SUPERUSER;', [input('pg_db')]) do
      its('output') { should match // }
    end

    describe command("grep -r \"must be superuser to create superusers\" #{input('pg_audit_log_dir')}") do
      its('stdout') { should match /^.*must be superuser to create superusers.*$/ }
    end

    describe sql.query('CREATE ROLE fooauditbad CREATEDB; CREATE ROLE fooauditbad CREATEROLE;', [input('pg_db')]) do
      its('output') { should match // }
    end

    describe command("grep -r \"permission denied to create role\" #{input('pg_audit_log_dir')}") do
      its('stdout') { should match /^.*permission denied to create role.*$/ }
    end
  else
    describe "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter." do
      skip "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter."
    end
  end
end
