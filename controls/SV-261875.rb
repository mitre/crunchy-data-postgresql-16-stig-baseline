control 'SV-261875' do
  title 'The audit information produced by PostgreSQL must be protected from unauthorized read access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to their advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions using file system protections and limiting log data location. 

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
  desc 'check', %q(Note: The following instructions use the PGLOG environment variable. Refer to supplementary content APPENDIX-I for instructions on configuring PGLOG.

Review locations of audit logs, both internal to the database and database audit logs located at the operating system level.

Verify appropriate controls and permissions exist to protect the audit information from unauthorized access.

#### syslog Logging

If PostgreSQL is configured to use syslog for logging, consult organization location and permissions for syslog log files.

#### stderr Logging

As the database administrator (shown here as "postgres"), check the current log_file_mode configuration by running the following:

Note: Consult the organization's documentation on acceptable log privileges.

$ sudo su - postgres
$ psql -c "SHOW log_file_mode"

If log_file_mode is not 600, this is a finding.

Verify the log files have the set permissions in ${PGLOG?}:

$ ls -l ${PGLOG?}/
total 32
-rw-------. 1 postgres postgres 0 Apr 8 00:00 postgresql-Fri.log
-rw-------. 1 postgres postgres 8288 Apr 11 17:36 postgresql-Mon.log
-rw-------. 1 postgres postgres 0 Apr 9 00:00 postgresql-Sat.log
-rw-------. 1 postgres postgres 0 Apr 10 00:00 postgresql-Sun.log
-rw-------. 1 postgres postgres 16212 Apr 7 17:05 postgresql-Thu.log 
-rw-------. 1 postgres postgres 1130 Apr 6 17:56 postgresql-Wed.log 

If logs with 600 permissions do not exist in ${PGLOG?}, this is a finding.)
  desc 'fix', %q(Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER. 

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

#### syslog Logging

If PostgreSQL is configured to use syslog for logging, consult organization location and permissions for syslog log files.

#### stderr Logging

If PostgreSQL is configured to use stderr for logging, permissions of the log files can be set in postgresql.conf.

As the database administrator (shown here as "postgres"), edit the following settings of logs in the postgresql.conf file:

Note: Consult the organization's documentation on acceptable log privileges.

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_file_mode = 0600

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?})
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag gid: 'V-261875'
  tag rid: 'SV-261875r1000630_rule'
  tag stig_id: 'CD16-00-002000'
  tag fix_id: 'F-65637r1000629_fix'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9', 'AU-9 a']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW log_file_mode;', [input('pg_db')]) do
    its('output') { should match /0600/ }
  end

  command("find #{input('pg_audit_log_dir')} -type f").stdout.split.each do |logfile|
    describe file(logfile) do
      its('mode') { should cmp '0600' }
    end
  end
end
