control 'SV-261909' do
  title 'PostgreSQL must reveal detailed error messages only to the information system security officer (ISSO), information system security manager (ISSM), system administrator (SA), and database administrator (DBA).'
  desc %q(If the DBMS provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements. 

Some default PostgreSQL error messages can contain information that could aid an attacker in, among other things, identifying the database type, host address, or state of the database. Custom errors may contain sensitive customer information. 

It is important that detailed error messages be visible only to those who are authorized to view them; that general users receive only generalized acknowledgment that errors have occurred; and that these generalized messages appear only when relevant to the user's task. For example, a message along the lines of, "An error has occurred. Unable to save your changes. If this problem persists, please contact your help desk" would be relevant. A message such as "Warning: your transaction generated a large number of page splits" would likely not be relevant. 

Administrative users authorized to review detailed error messages typically are the ISSO, ISSM, SA, and DBA. Other individuals or roles may be specified according to organization-specific needs, with appropriate approval.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the DBA is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.)
  desc 'check', "(Note: The following instructions use the PGDATA and PGLOG environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for instructions on configuring PGLOG.

Check PostgreSQL settings and custom database code to determine if detailed error messages are ever displayed to unauthorized individuals.

To check the level of detail for errors exposed to clients, as the DBA (shown here as \"postgres\"), run the following:

$ sudo su - postgres
$ psql -c \"SHOW client_min_messages;\"

If client_min_messages is not set to error, this is a finding.

If detailed error messages are displayed to individuals not authorized to view them, this is a finding.

#### stderr Logging

Logs may contain detailed information and should only be accessible by the database owner.

As the database administrator, verify the following settings of logs.

Note: Consult the organization's documentation on acceptable log privileges.

$ sudo su - postgres
$ psql -c \"SHOW log_file_mode;\" 

Verify the log files have the set configurations.

$ ls -l ${PGLOG?}
total 32
-rw-------. 1 postgres postgres 0 Apr 8 00:00 postgresql-Fri.log
-rw-------. 1 postgres postgres 8288 Apr 11 17:36 postgresql-Mon.log
-rw-------. 1 postgres postgres 0 Apr 9 00:00 postgresql-Sat.log
-rw-------. 1 postgres postgres 0 Apr 10 00:00 postgresql-Sun.log
-rw-------. 1 postgres postgres 16212 Apr 7 17:05 postgresql-Thu.log
-rw-------. 1 postgres postgres 1130 Apr 6 17:56 postgresql-Wed.log

If logs are not owned by the database administrator or have permissions that are not 0600, this is a finding.

#### syslog Logging

If PostgreSQL is configured to use syslog for logging, consult organization location and permissions for syslog log files. If the logs are not owned by root or have permissions that are not 0600, this is a finding.)
  desc 'fix', 'Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

To set the level of detail for error messages exposed to clients, as the DBA (shown here as \"postgres\"), run the following commands:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
client_min_messages = error'"
  impact 0.5
  tag check_id: 'C-65763r1000972_chk'
  tag severity: 'medium'
  tag gid: 'V-261909'
  tag rid: 'SV-261909r1000980_rule'
  tag stig_id: 'CD16-00-006100'
  tag gtitle: 'SRG-APP-000267-DB-000163'
  tag fix_id: 'F-65671r1000731_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW log_file_mode;',  [input('pg_db')]) do
    its('output') { should_not match /log|debug|LOG|DEBUG/ }
    its('output') { should match /^error$/i }
    end
end
