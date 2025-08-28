control 'SV-261884' do
  title 'Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers, links to software external to the DBMS, etc.) must be owned by database/PostgreSQL principals authorized for ownership.'
  desc "Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who uses the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

Conversely, if critical tables or other objects rely on unauthorized owner accounts, these objects may be lost when an account is removed."
  desc 'check', %q(Review system documentation to identify accounts authorized to own database objects. Review accounts that own objects in the database(s).

If any database objects are found to be owned by users not authorized to own database objects, this is a finding.

To check the ownership of objects in the database, as the database administrator, run the following SQL:

$ sudo su - postgres
$ psql -X -c '\dnS'
$ psql -x -c "\dt *.*"
$ psql -X -c '\dsS'
$ psql -x -c "\dv *.*"
$ psql -x -c "\df+ *.*"

If any object is not owned by an authorized role for ownership, this is a finding.)
  desc 'fix', 'Assign ownership of authorized objects to authorized object owner accounts.

#### Schema Owner

To create a schema owned by the user "bob", run the following SQL:

$ sudo su - postgres
$ psql -c "CREATE SCHEMA test AUTHORIZATION bob" 

To alter the ownership of an existing object to be owned by the user "bob", run the following SQL:

$ sudo su - postgres
$ psql -c "ALTER SCHEMA test OWNER TO bob"'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag gid: 'V-261884'
  tag rid: 'SV-261884r1000657_rule'
  tag stig_id: 'CD16-00-002900'
  tag fix_id: 'F-65646r1000656_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  databases_sql = "SELECT datname FROM pg_catalog.pg_database where datname = '#{input('pg_db')}';"
  databases_query = sql.query(databases_sql, [input('pg_db')])
  databases = databases_query.lines
  types = %w(t s v) # tables, sequences views

  databases.each do |database|
    schemas_sql = ''
    functions_sql = ''

    if database == 'postgres'
      schemas_sql = 'SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner) '\
        'FROM pg_catalog.pg_namespace n '\
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{input('pg_owner')}' AND pg_catalog.pg_get_userbyid(n.nspowner) <> 'pg_database_owner';"
      functions_sql = 'SELECT n.nspname, p.proname, '\
        'pg_catalog.pg_get_userbyid(n.nspowner) '\
        'FROM pg_catalog.pg_proc p '\
        'LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace '\
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{input('pg_owner')}' AND pg_catalog.pg_get_userbyid(n.nspowner) <> 'pg_database_owner';"
    else
      schemas_sql = 'SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner) '\
        'FROM pg_catalog.pg_namespace n '\
        'WHERE pg_catalog.pg_get_userbyid(n.nspowner) '\
        "NOT IN (#{input('pg_superusers').map { |e| "'#{e}'" }.join(',')}) "\
        "AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema';"
      functions_sql = 'SELECT n.nspname, p.proname, '\
        'pg_catalog.pg_get_userbyid(n.nspowner) '\
        'FROM pg_catalog.pg_proc p '\
        'LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace '\
        'WHERE pg_catalog.pg_get_userbyid(n.nspowner) '\
        "NOT IN (#{input('pg_superusers').map { |e| "'#{e}'" }.join(',')}) "\
        "AND n.nspname <> 'pg_catalog' AND n.nspname <> 'information_schema';"
    end

    connection_error = "FATAL:\\s+database \"#{database}\" is not currently "\
    'accepting connections'
    connection_error_regex = Regexp.new(connection_error)

    sql_result = sql.query(schemas_sql, [database])

    describe.one do
      describe sql_result do
        its('output') { should eq '' }
      end

      describe sql_result do
        it { should match connection_error_regex }
      end
    end

    sql_result = sql.query(functions_sql, [database])

    describe.one do
      describe sql_result do
        its('output') { should eq '' }
      end

      describe sql_result do
        it { should match connection_error_regex }
      end
    end

    types.each do |type|
      objects_sql = ''

      if database == 'postgres'
        objects_sql = 'SELECT n.nspname, c.relname, c.relkind, '\
        'pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_class c '\
        'LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace '\
        "WHERE c.relkind IN ('#{type}','s','') "\
        "AND pg_catalog.pg_get_userbyid(n.nspowner) <> '#{input('pg_owner')}' "
        "AND n.nspname !~ '^pg_toast';"
      else
        objects_sql = 'SELECT n.nspname, c.relname, c.relkind, '\
        'pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_class c '\
        'LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace '\
        "WHERE c.relkind IN ('#{type}','s','') "\
        'AND pg_catalog.pg_get_userbyid(n.nspowner) '\
        "NOT IN (#{input('pg_superusers').map { |e| "'#{e}'" }.join(',')}) "\
        "AND n.nspname <> 'pg_catalog' AND n.nspname <> 'information_schema'"\
        " AND n.nspname !~ '^pg_toast';"
      end

      sql_result = sql.query(objects_sql, [database])

      describe.one do
        describe sql_result do
          its('output') { should eq '' }
        end

        describe sql_result do
          it { should match connection_error_regex }
        end
      end
    end
  end
end
