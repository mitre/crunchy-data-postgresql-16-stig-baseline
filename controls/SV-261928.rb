control 'SV-261928' do
  title "PostgreSQL must use NSA-approved cryptography to protect classified information in accordance with the data owner's requirements."
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

NSA-approved cryptography for classified networks is hardware based. This requirement addresses the compatibility of PostgreSQL with the encryption devices.'
  desc 'check', 'If PostgreSQL is deployed in an unclassified environment, this is not applicable.

If PostgreSQL is not using NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards, this is a finding.

To check if PostgreSQL is configured to use SSL, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "SHOW ssl"

If SSL is off, this is a finding.

Consult network administration staff to determine whether the server is protected by NSA-approved encrypting devices. If not, this a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To configure PostgreSQL to use SSL as a database administrator (shown here as "postgres"), edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameter:

ssl = on

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

Deploy NSA-approved encrypting devices to protect the server on the network.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000416-DB-000380'
  tag gid: 'V-261928'
  tag rid: 'SV-261928r1000789_rule'
  tag stig_id: 'CD16-00-008300'
  tag fix_id: 'F-65690r1000788_fix'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13', 'SC-13 b']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW ssl;', [input('pg_db')]) do
    its('output') { should match /on|true/i }
  end
end
