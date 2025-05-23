control 'SV-261933' do
  title 'PostgreSQL must maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

This requirement applies only to those applications that are either distributed or can allow access to data nonlocally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When receiving data, PostgreSQL, associated applications, and infrastructure must leverage protection mechanisms.'
  desc 'check', 'If the data owner does not have a strict requirement for ensuring data integrity and
	confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.

As the database administrator (shown here as "postgres"), verify SSL is enabled in postgresql.conf by running
the following SQL:

$ sudo su - postgres
$ psql -c "SHOW ssl"

If SSL is off, this is a finding.

If PostgreSQL, associated applications, and infrastructure do not employ protective measures against unauthorized
	disclosure and modification during reception, this is a finding.'
  desc 'fix', 'Implement protective measures against unauthorized disclosure and modification during reception.

To configure PostgreSQL to use SSL, refer to supplementary content APPENDIX-G for instructions on enabling SSL.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000442-DB-000379'
  tag gid: 'V-261933'
  tag rid: 'SV-261933r1000804_rule'
  tag stig_id: 'CD16-00-008900'
  tag fix_id: 'F-65695r1000803_fix'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW ssl;', [input('pg_db')]) do
    its('output') { should_not match /off|false/i }
  end
end
