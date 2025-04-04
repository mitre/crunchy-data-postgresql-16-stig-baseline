control 'SV-261888' do
  title 'Access to external executables must be disabled or restricted.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives.

Applications must adhere to the principles of least functionality by providing only essential capabilities.

PostgreSQL may spawn additional external processes to execute procedures that are defined in PostgreSQL but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than PostgreSQL and provide unauthorized access to the host system.'
  desc 'check', %q(PostgreSQL's COPY command can interact with the underlying OS. Only superuser has access to this command.

As the database administrator (shown here as "postgres"), run the following SQL to list all roles and their privileges:

$ sudo su - postgres
$ psql -x -c "\du"

If any role has "superuser" that should not, this is a finding.

It is possible for an extension to contain code that could access external executables via SQL. To list all installed extensions, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -x -c "SELECT * FROM pg_available_extensions WHERE installed_version IS NOT NULL"

If any installed extensions are not approved, this is a finding.)
  desc 'fix', 'To remove superuser from a role, as the database administrator (shown here as "postgres"), run
	the following SQL:

$ sudo su - postgres
$ psql -c "ALTER ROLE <role-name> WITH NOSUPERUSER"

To remove extensions from PostgreSQL, as the database administrator (shown here as "postgres"), run the following
SQL:

$ sudo su - postgres
$ psql -c "DROP EXTENSION extension_name"'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag gid: 'V-261888'
  tag rid: 'SV-261888r1000669_rule'
  tag stig_id: 'CD16-00-003400'
  tag fix_id: 'F-65650r1000668_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

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

  describe sql.query("select * from pg_shadow where usename <> 'postgres' and usesuper = 't';", [input('pg_db')]) do
    its('output') { should match '' }
  end

  # @todo how do I check to see if any extensions are installed that are not approved?  fix stdout value?

  describe.one do
    input('approved_ext').each do |extension|
      describe sql.query('SELECT * FROM pg_available_extensions WHERE installed_version IS NOT NULL;', [input('pg_db')]) do
        its('output') { should match extension }
      end
    end
  end
end
