control 'SV-261967' do
  title 'PostgreSQL must offload audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for standalone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.

PostgreSQL may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with offloading the records to the centralized system.'
  desc 'check', 'As the database administrator (shown here as "postgres"), ensure PostgreSQL uses syslog by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW log_destination"

If log_destination is not syslog, this is a finding.

As the database administrator, check which log facility is configured by running the following SQL:

$ psql -c "SHOW syslog_facility" 

Check with the organization to refer to how syslog facilities are defined in their organization.

If the wrong facility is configured, this is a finding.

If PostgreSQL does not have a continuous network connection to the centralized log management system, and PostgreSQL audit records are not transferred to the centralized log management system weekly or more often, this is a finding.'
  desc 'fix', %q(Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Configure PostgreSQL or deploy and configure software tools to transfer audit records to a centralized log management system, continuously and in near real time where a continuous network connection to the log management system exists, or at least weekly in the absence of such a connection.

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

With logging enabled, as the database administrator (shown here as "postgres"), configure the following parameters in postgresql.conf (the example uses the default values - tailor for environment):

Note: Consult the organization on how syslog facilities are defined in the syslog daemon configuration.

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_destination = 'syslog'
syslog_facility = 'LOCAL0'
syslog_ident = 'postgres'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?})
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag gid: 'V-261967'
  tag rid: 'SV-261967r1000906_rule'
  tag stig_id: 'CD16-00-012400'
  tag fix_id: 'F-65729r1000905_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW log_destination;', [input('pg_db')]) do
    its('output') { should cmp 'csvlog,syslog' }
  end

  # Change comparison value based on organizational syslog defintions
  describe sql.query('SHOW syslog_facility;', [input('pg_db')]) do
    its('output') { should cmp 'local0' }
  end

  describe 'Configure PostgreSQL or deploy and configure software tools to transfer audit records to a centralized log management system' do
    skip 'If continuous network connection to the log management system does not exist, or at least weekly in the absence of such a connection. This is a finding'
  end
end
