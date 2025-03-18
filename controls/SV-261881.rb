control 'SV-261881' do
  title 'PostgreSQL must limit privileges to change software modules, to include stored procedures, functions and triggers, and links to software external to PostgreSQL.'
  desc 'If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

As the database administrator (shown here as "postgres"), check the permissions of configuration files for the database:

$ sudo su - postgres
$ ls -la ${PGDATA?}

If any files are not owned by the database owner or have permissions allowing others to modify (write) configuration files, this is a finding.

As the server administrator, check the permissions on the shared libraries for PostgreSQL:

$ sudo ls -la /usr/pgsql-${PGVER?} 
$ sudo ls -la /usr/pgsql-${PGVER?}/bin
$ sudo ls -la /usr/pgsql-${PGVER?}/include
$ sudo ls -la /usr/pgsql-${PGVER?}/lib
$ sudo ls -la /usr/pgsql-${PGVER?}/share

If any files are not owned by root or have permissions allowing others to modify (write) configuration files, this is a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

As the database administrator (shown here as "postgres"), change the ownership and permissions of configuration files in PGDATA: 

$ sudo su - postgres 
$ chown postgres:postgres ${PGDATA?}/postgresql.conf 
$ chmod 0600 ${PGDATA?}/postgresql.conf 

As the server administrator, change the ownership and permissions of shared objects in /usr/pgsql-${PGVER?}/*.so 

$ sudo chown root:root /usr/pgsql-${PGVER?}/lib/*.so 
$ sudo chmod 0755 /usr/pgsql-${PGVER?}/lib/*.so 

As the service administrator, change the ownership and permissions of executables in /usr/pgsql-${PGVER?}/bin: 

$ sudo chown root:root /usr/pgsql-${PGVER?}/bin/* 
$ sudo chmod 0755 /usr/pgsql-${PGVER?}/bin/*'
  impact 0.5
  tag check_id: 'C-65735r1000646_chk'
  tag severity: 'medium'
  tag gid: 'V-261881'
  tag rid: 'SV-261881r1000648_rule'
  tag stig_id: 'CD16-00-002600'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-65643r1000647_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  describe file(input('pg_conf_file')) do
    it { should be_owned_by input('pg_owner') }
    its('mode') { should cmp '0600' }
  end

  describe file(input('pg_hba_conf_file')) do
    it { should be_owned_by input('pg_owner') }
    its('mode') { should cmp '0600' }
  end

  describe file(input('pg_ident_conf_file')) do
    it { should be_owned_by input('pg_owner') }
    its('mode') { should cmp '0600' }
  end
end
