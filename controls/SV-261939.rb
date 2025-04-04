control 'SV-261939' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to access security objects occur.'
  desc 'Changes to the security configuration must be tracked.

This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality.

In an SQL environment, types of access include, but are not limited to:
SELECT
INSERT
UPDATE
DELETE
EXECUTE

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'Note: The following instructions use the PGDATA and PGLOG environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

As the database administrator (shown here as "postgres"), setup a test schema and revoke users privileges from using it by running the following SQL:

$ sudo su - postgres
$ psql -c "CREATE SCHEMA stig_test_schema AUTHORIZATION postgres"
$ psql -c "REVOKE ALL ON SCHEMA stig_test_schema FROM public"
$ psql -c "GRANT ALL ON SCHEMA stig_test_schema TO postgres"

Create a test table and insert a value into that table for the following checks by running the following SQL:

$ psql -c "CREATE TABLE stig_test_schema.stig_test_table(id INT)"
$ psql -c "INSERT INTO stig_test_schema.stig_test_table(id) VALUES (0)"

#### CREATE
Attempt to CREATE a table in the stig_test_schema schema with a role that does not have privileges by running the following SQL:

psql -c "CREATE ROLE bob; SET ROLE bob; CREATE TABLE stig_test_schema.test_table(id INT);"
ERROR: permission denied for schema stig_test_schema

As a database administrator (shown here as "postgres"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2024-03-09 09:55:19.423 UTC postgres 56e0393f.186b postgres: >ERROR: permission denied for schema stig_test_schema at character 14
< 2024-03-09 09:55:19.423 UTC postgres 56e0393f.186b postgres: >STATEMENT: CREATE TABLE stig_test_schema.test_table(id INT);

If the denial is not logged, this is a finding.

#### INSERT
As role bob, attempt to INSERT into the table created earlier, stig_test_table by running the following SQL:

$ sudo su - postgres
$ psql -c "SET ROLE bob; INSERT INTO stig_test_schema.stig_test_table(id) VALUES (0);"

As a database administrator (shown here as "postgres"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2024-03-09 09:58:30.709 UTC postgres 56e0393f.186b postgres: >ERROR: permission denied for schema stig_test_schema at character 13
< 2024-03-09 09:58:30.709 UTC postgres 56e0393f.186b postgres: >STATEMENT: INSERT INTO stig_test_schema.stig_test_table(id) VALUES (0);

If the denial is not logged, this is a finding.

#### SELECT
As role bob, attempt to SELECT from the table created earlier, stig_test_table by running the following SQL:

$ sudo su - postgres
$ psql -c "SET ROLE bob; SELECT * FROM stig_test_schema.stig_test_table;"

As a database administrator (shown here as "postgres"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2024-03-09 09:57:58.327 UTC postgres 56e0393f.186b postgres: >ERROR: permission denied for schema stig_test_schema at character 15
< 2024-03-09 09:57:58.327 UTC postgres 56e0393f.186b postgres: >STATEMENT: SELECT * FROM stig_test_schema.stig_test_table;

If the denial is not logged, this is a finding.

#### ALTER
As role bob, attempt to ALTER the table created earlier, stig_test_table by running the following SQL:

$ sudo su - postgres
$ psql -c "SET ROLE bob; ALTER TABLE stig_test_schema.stig_test_table ADD COLUMN name TEXT;"

As a database administrator (shown here as "postgres"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2024-03-09 10:03:43.765 UTC postgres 56e0393f.186b postgres: >STATEMENT: ALTER TABLE stig_test_schema.stig_test_table ADD COLUMN name TEXT;

If the denial is not logged, this is a finding.

#### UPDATE
As role bob, attempt to UPDATE a row created earlier, stig_test_table by running the following SQL:

$ sudo su - postgres
$ psql -c "SET ROLE bob; UPDATE stig_test_schema.stig_test_table SET id=1 WHERE id=0;"

As a database administrator (shown here as "postgres"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2024-03-09 10:08:27.696 UTC postgres 56e0393f.186b postgres: >ERROR: permission denied for schema stig_test_schema at character 8
< 2024-03-09 10:08:27.696 UTC postgres 56e0393f.186b postgres: >STATEMENT: UPDATE stig_test_schema.stig_test_table SET id=1 WHERE id=0;

If the denial is not logged, this is a finding.

#### DELETE
As role bob, attempt to DELETE a row created earlier, stig_test_table by running the following SQL:

$ sudo su - postgres
$ psql -c "SET ROLE bob; DELETE FROM stig_test_schema.stig_test_table WHERE id=0;"

As a database administrator (shown here as "postgres"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2024-03-09 10:09:29.607 UTC postgres 56e0393f.186b postgres: >ERROR: permission denied for schema stig_test_schema at character 13
< 2024-03-09 10:09:29.607 UTC postgres 56e0393f.186b postgres: >STATEMENT: DELETE FROM stig_test_schema.stig_test_table WHERE id=0;

If the denial is not logged, this is a finding.

#### PREPARE 
As role bob, attempt to execute a prepared system using PREPARE by running the following SQL:

$ sudo su - postgres
$ psql -c "SET ROLE bob; PREPARE stig_test_plan(int) AS SELECT id FROM stig_test_schema.stig_test_table WHERE id=$1;"

As a database administrator (shown here as "postgres"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2024-03-09 10:16:22.628 UTC postgres 56e03e02.18e4 postgres: >ERROR: permission denied for schema stig_test_schema at character 46
< 2024-03-09 10:16:22.628 UTC postgres 56e03e02.18e4 postgres: >STATEMENT: PREPARE stig_test_plan(int) AS SELECT id FROM stig_test_schema.stig_test_table WHERE id=$1;

If the denial is not logged, this is a finding.

#### DROP
As role bob, attempt to DROP the table created earlier stig_test_table by running the following SQL:

$ sudo su - postgres
$ psql -c "SET ROLE bob; DROP TABLE stig_test_schema.stig_test_table;"

As a database administrator (shown here as "postgres"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2024-03-09 10:18:55.255 UTC postgres 56e03e02.18e4 postgres: >ERROR: permission denied for schema stig_test_schema
< 2024-03-09 10:18:55.255 UTC postgres 56e03e02.18e4 postgres: >STATEMENT: DROP TABLE stig_test_schema.stig_test_table;

If the denial is not logged, this is a finding.'
  desc 'fix', 'Configure PostgreSQL to produce audit records when unsuccessful attempts to access security objects occur.

All denials are logged if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000492-DB-000333'
  tag gid: 'V-261939'
  tag rid: 'SV-261939r1000822_rule'
  tag stig_id: 'CD16-00-009500'
  tag fix_id: 'F-65701r1000821_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  if file(input('pg_audit_log_dir')).exist?

    describe sql.query('CREATE ROLE permdeniedtest; CREATE SCHEMA permdeniedschema; SET ROLE permdeniedtest; CREATE TABLE permdeniedschema.usertable(index int);', [input('pg_db')]) do
      its('output') { should match // }
    end

    # Find the most recently modified log file in the input('pg_audit_log_dir'), grep for the syntax error statement, and then
    # test to validate the output matches the regex.

    describe command("grep -r \"permission denied for schema\" #{input('pg_audit_log_dir')}") do
      its('stdout') { should match /^.*permission denied for schema permdeniedschema..*$/ }
    end

    describe sql.query('SET ROLE postgres; DROP SCHEMA IF EXISTS permdeniedschema; DROP ROLE IF EXISTS permdeniedtest;', [input('pg_db')]) do
      its('output') { should match // }
    end
  else
    describe "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter." do
      skip "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter."
    end
  end
end
