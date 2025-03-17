control 'SV-261878' do
  title 'PostgreSQL must protect its audit features from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. 

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access. 

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open-source audit tools needed to successfully view and manipulate audit information system activity and records. 

If an attacker were to gain access to audit tools, they could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity.'
  desc 'check', 'Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA, APPENDIX-H for PGVER, and APPENDIX-I for PGLOG. Only the database owner and superuser can alter configuration of PostgreSQL.

Ensure the PGLOG directory is owned by postgres user and group:

$ sudo su - postgres
$ ls -la ${PGLOG?} 

If PGLOG is not owned by the database owner, this is a finding. 

Ensure the data directory is owned by postgres user and group. 

$ sudo su - postgres
$ ls -la ${PGDATA?}

If PGDATA is not owned by the database owner, this is a finding.

Ensure the pgaudit installation is owned by root:

$ sudo su - postgres
$ ls -la /usr/pgsql-${PGVER?}/share/extension/pgaudit*

If the pgaudit installation is not owned by root, this is a finding.

As the database administrator (shown here as "postgres"), run the following SQL to list all roles and their privileges:

$ sudo su - postgres
$ psql -x -c "\\du"

If any role has "superuser" that should not, this is a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA, APPENDIX-H for PGVER and APPENDIX-I for PGLOG.

If PGLOG or PGDATA are not owned by postgres user and group, configure them as follows: 

$ sudo chown -R postgres:postgres ${PGDATA?}
$ sudo chown -R postgres:postgres ${PGLOG?}

If the pgaudit installation is not owned by root user and group, configure it as follows:

$ sudo chown -R root:root /usr/pgsql-${PGVER?}/share/extension/pgaudit*

To remove superuser from a role, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "ALTER ROLE <role-name> WITH NOSUPERUSER"'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag gid: 'V-261878'
  tag rid: 'SV-261878r1000958_rule'
  tag stig_id: 'CD16-00-002300'
  tag fix_id: 'F-65640r1000638_fix'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9', 'AU-9 a']

  describe directory(input('pg_log_dir')) do
    it { should be_owned_by input('pg_owner') }
    it { should be_grouped_into input('pg_group') }
  end

  describe directory(input('pg_data_dir')) do
    it { should be_owned_by input('pg_owner') }
    it { should be_grouped_into input('pg_group') }
  end

  describe directory(input('pgaudit_installation')) do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'
  roles_query = sql.query(roles_sql, [input('pg_db')])
  roles = roles_query.lines

  roles.each do |role|
    next if input('pg_superusers').include?(role)
    superuser_sql = 'SELECT r.rolsuper FROM pg_catalog.pg_roles r '\
    "WHERE r.rolname = '#{role}';"

    describe sql.query(superuser_sql, [input('pg_db')]) do
      its('output') { should_not eq 't' }
    end
  end
end
