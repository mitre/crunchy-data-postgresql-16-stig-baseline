control 'SV-261916' do
    desc 'check', 'Functions in PostgreSQL can be created with the SECURITY DEFINER
    option. When SECURITY DEFINER functions are executed by a user, said function
    is run with the privileges of the user who created it.
    To list all functions that have SECURITY DEFINER, as, the DBA (shown here as "postgres"), run the following SQL:
    $ sudo su - postgres
    $ psql -c "SELECT nspname, proname, proargtypes, prosecdef, rolname, proconfig
    FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN pg_roles a
    ON a.oid = p.proowner WHERE prosecdef OR NOT proconfig IS NULL"
    In the query results, a prosecdef value of "t" on a row indicates that that
    function uses privilege elevation.
    If elevation of PostgreSQL privileges is utilized but not documented, this is a
    finding.
    If elevation of PostgreSQL privileges is documented, but not implemented as
    described in the documentation, this is a finding.
    If the privilege-elevation logic can be invoked in ways other than intended, or
    in contexts other than intended, or by subjects/principals other than intended,
    this is a finding.'

    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))
    pg_db = input('pg_db')

    security_definer_sql = 'SELECT nspname, proname, prosecdef '\
      'FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid '\
      "JOIN pg_roles a ON a.oid = p.proowner WHERE prosecdef = 't';"

    databases_sql = "SELECT datname FROM pg_catalog.pg_database where datname = '#{pg_db}';"
    databases_query = sql.query(databases_sql, [pg_db])
    databases = databases_query.lines

    # User-specified list of allowed privilege escalation functions
    # Setting value: [] ensures the control won’t crash if privilege_escalation_functions isn’t defined at all.
    allowed_functions = input('privilege_escalation_functions', value: [])

    databases.each do |database|
      connection_error = "FATAL:\\s+database \"#{database}\" is not currently "\
        'accepting connections' 
      connection_error_regex = Regexp.new(connection_error)
      
      sql_result = sql.query(security_definer_sql, [database])
      
      describe.one do
        # Case 1: No allowed functions specified → ensure no privilege escalation functions are returned 
        if allowed_functions.empty?
          describe "SQL query result for database '#{database}'" do
            it 'should not return any privilege escalation functions (OK)' do
              expect(sql_result.lines.map(&:strip)).to be_empty.or match(connection_error_regex)
            end
          end
        else
          # Case 2: Validate returned functions against the allowed list 
          returned_functions = sql_result.lines.map { |line| line.split('|')[1].strip } # Extract function names
          returned_functions.each do |function_name|
            describe "Function '#{function_name}'" do
              it 'should be in the list of allowed privilege escalation functions (Trusted)' do
                expect(function_name).to be_in(allowed_functions)
              end
            end
          end
        end
      end
    end
  end
