control 'SV-261926' do
  title 'PostgreSQL must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accordance with the Ports, Protocols, and Services Management (PPSM) guidance.'
  desc 'Use of nonsecure network functions, ports, protocols, and services exposes the system to avoidable
	threats.'
  desc 'check', 'As the database administrator, run the following SQL:

$ psql -c "SHOW port"

If the currently defined port configuration is deemed prohibited, this is a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To change the listening port of the database, as the database administrator, change the following setting in postgresql.conf: 

$ sudo su - postgres 
$ vi $PGDATA/postgresql.conf 

Change the port parameter to the desired port. 

Restart the database: 

$ sudo systemctl restart postgresql-${PGVER?} 

Note: psql uses the port 5432 by default. This can be changed by specifying the port with psql or by setting the PGPORT environment variable: 

$ psql -p 5432 -c "SHOW port" 
$ export PGPORT=5432'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag gid: 'V-261926'
  tag rid: 'SV-261926r1000783_rule'
  tag stig_id: 'CD16-00-008000'
  tag fix_id: 'F-65688r1000782_fix'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']

  describe 'Check that all network functions, ports, protocols, and services comply with PPSM guidance' do
    skip 'If network functions, ports, procols, and services do not comply with PPSM guidance, this is a finding.'
  end
end
