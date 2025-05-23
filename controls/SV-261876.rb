control 'SV-261876' do
  title 'The audit information produced by PostgreSQL must be protected from unauthorized modification.'
  desc "If audit data were to become compromised, competent forensic analysis and discovery of the true source of potentially malicious system activity would be impossible to achieve. 

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification. 

This requirement can be achieved through multiple methods depending on system architecture and design. Some commonly employed methods include ensuring log files have the proper file system permissions and limiting log data locations. 

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the user's corresponding rights to make access decisions regarding the modification of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 

Modification of database audit data could mask the theft or unauthorized modification of sensitive data stored in the database."
  desc 'check', 'Review locations of audit logs, both internal to the database and database audit logs located at the operating system level. 

Verify there are appropriate controls and permissions to protect the audit information from unauthorized modification. 

Note: The following instructions use the PGLOG environment variable. Refer to supplementary content APPENDIX-I for instructions on configuring PGLOG. 

#### stderr Logging 

If the PostgreSQL server is configured to use stderr for logging, the logs will be owned by the database owner (usually postgres user) with a default permissions level of 0600. The permissions can be configured in postgresql.conf. 

To check the permissions for log files in postgresql.conf, as the database owner (shown here as "postgres"), run the following command: 

$ sudo su - postgres 
$ psql -c "show log_file_mode;" 

If the permissions are not 0600, this is a finding. 

As the database owner (shown here as "postgres"), list the permissions of the logs: 

$ sudo su - postgres 
$ ls -la ${PGLOG?} 

If logs are not owned by the database owner (shown here as "postgres") and are not the same permissions as configured in postgresql.conf, this is a finding. 

#### syslog Logging 

If the PostgreSQL server is configured to use syslog for logging, consult the organization syslog setting for permissions and ownership of logs.'
  desc 'fix', 'To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for instructions on configuring PGLOG.

#### stderr Logging

With stderr logging enabled, as the database owner (shown here as "postgres"), set the following parameter in postgresql.conf:

$ vi ${PGDATA?}/postgresql.conf
log_file_mode = 0600

To change the owner and permissions of the log files, run the following:

$ chown postgres:postgres ${PGDATA?}/${PGLOG?}
$ chmod 0700 ${PGDATA?}/${PGLOG?}
$ chmod 600 ${PGDATA?}/${PGLOG?}/*.log

#### syslog Logging

If PostgreSQL is configured to use syslog for logging, the log files must be configured to be owned by root with 0600 permissions.

$ chown root:root <log directory name>/<log_filename>
$ chmod 0700 <log directory name>
$ chmod 0600 <log directory name>/*.log'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000119-DB-000060'
  tag gid: 'V-261876'
  tag rid: 'SV-261876r1000978_rule'
  tag stig_id: 'CD16-00-002100'
  tag fix_id: 'F-65638r1000632_fix'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9', 'AU-9 a']

  pg_owner = input('pg_owner')

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW log_file_mode;', [input('pg_db')]) do
    its('output') { should cmp '0600' }
  end

  describe sql.query('SHOW logging_collector;', [input('pg_db')]) do
    its('output') { should_not match /off|false/i }
  end

  describe directory(input('pg_log_dir')) do
    it { should be_directory }
    it { should be_owned_by pg_owner }
    it { should be_grouped_into pg_owner }
    its('mode') { should  cmp '0700' }
  end

  describe command("find #{input('pg_log_dir')} -type f -perm 600 ! -perm 600 | wc -l") do
    its('stdout.strip') { should eq '0' }
  end
end
