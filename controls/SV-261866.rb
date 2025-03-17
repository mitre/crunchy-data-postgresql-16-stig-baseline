control 'SV-261866' do
  title 'PostgreSQL must produce audit records containing sufficient information to establish what type of
	events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. 

PostgreSQL is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly what actions were performed. This requires specific information regarding the event type an audit record is referring to. If event type information is not recorded and stored with the audit record, the record itself is of very limited use.'
  desc 'check', 'As the database administrator (shown here as "postgres"), verify the current log_line_prefix setting:

$ sudo su - postgres
$ psql -c "SHOW log_line_prefix"

Verify that the current settings are appropriate for the organization.

The following is what is possible for logged information:

# %a = application name
# %u = user name
# %d = database name
# %r = remote host and port
# %h = remote host
# %p = process ID
# %t = timestamp without milliseconds
# %m = timestamp with milliseconds
# %i = command tag
# %e = SQL state
# %c = session ID
# %l = session line number
# %s = session start timestamp
# %v = virtual transaction ID
# %x = transaction ID (0 if none)
# %q = stop here in non-session processes

If the audit record does not log events required by the organization, this is a finding.

Verify the current settings of log_connections and log_disconnections by running the following SQL:

$ psql -c "SHOW log_connections"
$ psql -c "SHOW log_disconnections"

If either setting is off, this is a finding.'
  desc 'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C. 

If logging is enabled the following configurations must be made to log connections, date/time, username and session identifier.

Edit the postgresql.conf file as a privileged user:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Edit the following parameters based on the organization's needs (minimum requirements are as follows):

log_connections = on
log_disconnections = on
log_line_prefix = '< %m %u %d %c: >'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000095-DB-000039'
  tag gid: 'V-261866'
  tag rid: 'SV-261866r1000603_rule'
  tag stig_id: 'CD16-00-001000'
  tag fix_id: 'F-65628r1000602_fix'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3', 'AU-3 a']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  log_line_prefix_escapes = %w(%m %u %d %s)
  log_line_prefix_escapes.each do |escape|
    describe sql.query('SHOW log_line_prefix;', [input('pg_db')]) do
      its('output') { should include escape }
    end
  end

  describe sql.query('SHOW log_connections;', [input('pg_db')]) do
    its('output') { should_not match /off|false/i }
  end

  describe sql.query('SHOW log_disconnections;', [input('pg_db')]) do
    its('output') { should_not match /off|false/i }
  end
end
