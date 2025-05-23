control 'SV-261963' do
  title 'PostgreSQL must generate audit records when unsuccessful accesses to objects occur.'
  desc 'Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

In an SQL environment, types of access include, but are not limited to:
SELECT
INSERT
UPDATE
DELETE
EXECUTE

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'Note: The following instructions use the PGDATA and PGLOG environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

As the database administrator (shown here as "postgres"), create a schema, test_schema, create a table, test_table, within test_schema, and insert a value:

$ sudo su - postgres
$ psql -c "CREATE SCHEMA test_schema"
$ psql -c "CREATE TABLE test_schema.test_table(id INT)"
$ psql -c "INSERT INTO test_schema.test_table(id) VALUES (0)"

Create a role "bob" and attempt to SELECT, INSERT, UPDATE, and DROP from the test table: 

$ psql -c "CREATE ROLE BOB"
$ psql -c "SET ROLE bob; SELECT * FROM test_schema.test_table"

$ psql -c "SET ROLE bob; INSERT INTO test_schema.test_table VALUES (0)"
$ psql -c "SET ROLE bob; UPDATE test_schema.test_table SET id = 1 WHERE id = 0"
$ psql -c "SET ROLE bob; DROP TABLE test_schema.test_table"
$ psql -c "SET ROLE bob; DROP SCHEMA test_schema"

As the database administrator (shown here as "postgres"), review PostgreSQL/database security and audit settings to verify that audit records are created for unsuccessful attempts at the specified access to the specified objects:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
2024-03-30 17:23:41.254 EDT postgres postgres ERROR: permission denied for schema test_schema at character 15
2024-03-30 17:23:41.254 EDT postgres postgres STATEMENT: SELECT * FROM test_schema.test_table;
2024-03-30 17:23:53.973 EDT postgres postgres ERROR: permission denied for schema test_schema at character 13
2024-03-30 17:23:53.973 EDT postgres postgres STATEMENT: INSERT INTO test_schema.test_table VALUES (0);
2024-03-30 17:24:32.647 EDT postgres postgres ERROR: permission denied for schema test_schema at character 8
2024-03-30 17:24:32.647 EDT postgres postgres STATEMENT: UPDATE test_schema.test_table SET id = 1 WHERE id = 0;
2024-03-30 17:24:46.197 EDT postgres postgres ERROR: permission denied for schema test_schema
2024-03-30 17:24:46.197 EDT postgres postgres STATEMENT: DROP TABLE test_schema.test_table;
2024-03-30 17:24:51.582 EDT postgres postgres ERROR: must be owner of schema test_schema
2024-03-30 17:24:51.582 EDT postgres postgres STATEMENT: DROP SCHEMA test_schema;

If any of the above steps did not create audit records for SELECT, INSERT, UPDATE, and DROP, this is a finding.'
  desc 'fix', 'Configure PostgreSQL to produce audit records when unsuccessful attempts to access objects occur.

All errors and denials are logged if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000507-DB-000357'
  tag gid: 'V-261963'
  tag rid: 'SV-261963r1000894_rule'
  tag stig_id: 'CD16-00-011900'
  tag fix_id: 'F-65725r1000893_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  if file(input('pg_audit_log_dir')).exist?

    describe sql.query('DROP TABLE IF EXISTS test_schema.test_table;', [input('pg_db')]) do
      its('output') { should eq 'DROP TABLE' }
    end

    describe sql.query('DROP SCHEMA IF EXISTS test_schema;', [input('pg_db')]) do
      its('output') { should eq 'DROP SCHEMA' }
    end

    describe sql.query('CREATE SCHEMA test_schema;', [input('pg_db')]) do
      its('output') { should eq 'CREATE SCHEMA' }
    end

    describe sql.query('CREATE TABLE test_schema.test_table(id INT);', [input('pg_db')]) do
      its('output') { should eq 'CREATE TABLE' }
    end

    describe sql.query('INSERT INTO test_schema.test_table(id) VALUES (0);', [input('pg_db')]) do
      its('output') { should eq 'INSERT 0 1' }
    end

    describe sql.query('CREATE ROLE bob;', [input('pg_db')]) do
      its('output') { should eq 'CREATE ROLE' }
    end

    describe sql.query('SET ROLE bob; SELECT * FROM test_schema.test_table;', [input('pg_db')]) do
      its('output') { should match /ERROR:  permission denied for schema test_schema/ }
    end

    describe sql.query('SET ROLE bob; INSERT INTO test_schema.test_table VALUES (0);', [input('pg_db')]) do
      its('output') { should match /ERROR:  permission denied for schema test_schema/ }
    end

    describe sql.query('SET ROLE bob; UPDATE test_schema.test_table SET id = 1 WHERE id = 0;', [input('pg_db')]) do
      its('output') { should match /ERROR:  permission denied for schema test_schema/ }
    end

    describe sql.query('SET ROLE bob; DROP TABLE test_schema.test_table;', [input('pg_db')]) do
      its('output') { should match /ERROR:  permission denied for schema test_schema/ }
    end

    describe sql.query('SET ROLE bob; DROP SCHEMA test_schema;', [input('pg_db')]) do
      its('output') { should match /ERROR:  must be owner of schema test_schema/ }
    end

    describe sql.query('DROP ROLE bob;', [input('pg_db')]) do
    end

    describe command("grep -r \"permission denied for schema test_schema\" #{input('pg_audit_log_dir')}") do
      its('stdout') { should match /^.*permission denied for schema test_schema.*$/ }
    end

    describe command("grep -r \"must be owner of schema test_schema\" #{input('pg_audit_log_dir')}") do
      its('stdout') { should match /^.*must be owner of schema test_schema.*$/ }
    end

  else
    describe "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter." do
      skip "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter."
    end
  end
end
