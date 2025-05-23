control 'SV-261917' do
  title 'PostgreSQL must use centralized management of the content captured in audit records generated by all components of PostgreSQL.'
  desc 'Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. 

PostgreSQL may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with offloading the records to the centralized system.'
  desc 'check', 'On Unix systems, PostgreSQL can be configured to use stderr, csvlog, and syslog. To send logs to a centralized location, syslog should be used.

As the database owner (shown here as "postgres"), ensure PostgreSQL uses syslog by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW log_destination"

As the database owner (shown here as "postgres"), check to which log facility PostgreSQL is configured by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW syslog_facility"

Check with the organization to refer to how syslog facilities are defined in their organization.

If PostgreSQL audit records are not written directly to or systematically transferred to a centralized log management system, this is a finding.'
  desc 'fix', %q(Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER. 

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

With logging enabled, as the database owner {shown here as "postgres"} configure the following parameters in postgresql.conf:

Note: Consult the organization on how syslog facilities are defined in the syslog daemon configuration.

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_destination = 'syslog'
syslog_facility = 'LOCAL0'
syslog_ident = 'postgres'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?})
  impact 0.5
  tag check_id: 'C-65771r1000962_chk'
  tag severity: 'medium'
  tag gid: 'V-261917'
  tag rid: 'SV-261917r1000962_rule'
  tag stig_id: 'CD16-00-007000'
  tag gtitle: 'SRG-APP-000356-DB-000314'
  tag fix_id: 'F-65679r1000755_fix'
  tag 'documentable'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))
  
  describe sql.query('SHOW log_destination;', [input('pg_db')]) do
    its('output') { should include 'syslog' }
  end
  
  describe sql.query('SHOW syslog_facility;', [input('pg_db')]) do
    its('output') { should cmp 'LOCAL0' }    
  end
end