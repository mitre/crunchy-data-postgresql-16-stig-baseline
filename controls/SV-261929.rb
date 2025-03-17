control 'SV-261929' do
  title 'PostgreSQL must only accept end entity certificates issued by DOD PKI or DOD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.'
  desc 'Only DOD-approved external PKIs have been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DOD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.

The authoritative list of DOD-approved PKIs is published at https://public.cyber.mil/pki-pke/interoperability/.

This requirement focuses on communications protection for the PostgreSQL session rather than for the network packet.'
  desc 'check', 'As the database administrator (shown here as "postgres"), verify the following setting in postgresql.conf:

$ sudo su - postgres
$ psql -c "SHOW ssl_ca_file"
$ psql -c "SHOW ssl_cert_file"

If the database is not configured to use only DOD-approved certificates, this is a finding.'
  desc 'fix', 'Revoke trust in any certificates not issued by a DOD-approved certificate authority.

Configure PostgreSQL to accept only DOD and DOD-approved PKI end-entity certificates.

To configure PostgreSQL to accept approved CAs, refer to the official PostgreSQL documentation: http://www.postgresql.org/docs/current/static/ssl-tcp.html

For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000427-DB-000385'
  tag gid: 'V-261929'
  tag rid: 'SV-261929r1000792_rule'
  tag stig_id: 'CD16-00-008400'
  tag fix_id: 'F-65691r1000791_fix'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW ssl_ca_file;', [input('pg_db')]) do
    its('output') { should_not eq '' }
  end

  describe sql.query('SHOW ssl_cert_file;', [input('pg_db')]) do
    its('output') { should_not eq '' }
  end
end
