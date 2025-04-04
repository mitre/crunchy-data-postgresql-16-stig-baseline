control 'SV-261932' do
  title 'PostgreSQL must maintain the confidentiality and integrity of information during preparation for
	transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.

When transmitting data, PostgreSQL, associated applications, and infrastructure must leverage transmission protection mechanisms.'
  desc 'check', 'If the data owner does not have a strict requirement for ensuring data integrity and
	confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.

As the database administrator (shown here as "postgres"), verify SSL is enabled by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW ssl"

If SSL is not enabled, this is a finding.

If PostgreSQL does not employ protective measures against unauthorized disclosure and modification during
preparation for transmission, this is a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Implement protective measures against unauthorized disclosure and modification during preparation for transmission.

To configure PostgreSQL to use SSL, as a database administrator (shown here as "postgres"), edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameter:

ssl = on

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag gid: 'V-261932'
  tag rid: 'SV-261932r1000801_rule'
  tag stig_id: 'CD16-00-008800'
  tag fix_id: 'F-65694r1000800_fix'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW ssl;', [input('pg_db')]) do
    its('output') { should match /on|true/i }
  end
end
