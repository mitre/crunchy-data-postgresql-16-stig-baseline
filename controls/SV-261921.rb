control 'SV-261921' do
  title 'PostgreSQL must record time stamps in audit records and application data that can be mapped to Coordinated Universal Time (UTC), formerly Greenwich Mean Time (GMT).'
  desc 'If time stamps are not consistently applied and there is no common time reference, it is difficult to perform forensic analysis.

Time stamps generated by PostgreSQL must include date and time. Time is commonly expressed in UTC, a modern continuation of GMT, or local time with an offset from UTC.

Some DBMS products offer a data type called TIMESTAMP that is not a representation of date and time. Rather, it is a database state counter and does not correspond to calendar and clock time. This requirement does not refer to that meaning of TIMESTAMP.'
  desc 'check', 'When a PostgreSQL cluster is initialized using initdb, the PostgreSQL cluster will be
	configured to use the same time zone as the target server.

As the database administrator (shown here as "postgres"), check the current log_timezone setting by running
the following SQL:

$ sudo su - postgres
$ psql -c "SHOW log_timezone"

log_timezone
--------------
UTC
(1 row)

If log_timezone is not set to the desired time zone, this is a finding.'
  desc 'fix', %q(Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To change log_timezone in postgresql.conf to use a different time zone for logs, as the database administrator (shown here as "postgres"), run the following:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_timezone='UTC'

Restart the database:

$ sudo systemctl reload postgresql-${PGVER?})
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000374-DB-000322'
  tag gid: 'V-261921'
  tag rid: 'SV-261921r1000994_rule'
  tag stig_id: 'CD16-00-007500'
  tag fix_id: 'F-65683r1000767_fix'
  tag cci: ['CCI-001890']
  tag nist: ['AU-8 b']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW log_timezone;', [input('pg_db')]) do
    its('output') { should eq input('pg_timezone') }
  end
end
