control 'SV-261916' do
  title 'Execution of software modules (to include stored procedures, functions, and triggers) with elevated privileges must be restricted to necessary cases only.'
  desc 'In certain situations, to provide required functionality, PostgreSQL needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.

Privilege elevation must be used only where necessary and protected from misuse.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', 'Functions in PostgreSQL can be created with the SECURITY DEFINER option. When SECURITY DEFINER functions are executed by a user, said function is run with the privileges of the user who created it.

To list all functions that have SECURITY DEFINER, as, the DBA (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "SELECT nspname, proname, proargtypes, prosecdef, rolname, proconfig FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN pg_authid a ON a.oid = p.proowner WHERE prosecdef OR NOT proconfig IS NULL"

In the query results, a prosecdef value of "t" on a row indicates that that function uses privilege elevation.

If elevation of PostgreSQL privileges is used but not documented, this is a finding.

If elevation of PostgreSQL privileges is documented, but not implemented as described in the documentation, this is a finding.

If the privilege-elevation logic can be invoked in ways other than intended, or in contexts other than intended, or by subjects/principals other than intended, this is a finding.'
  desc 'fix', 'Determine where, when, how, and by what principals/subjects elevated privilege is needed.

To change a SECURITY DEFINER function to SECURITY INVOKER, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "ALTER FUNCTION <function_name> SECURITY INVOKER"'
  impact 0.5
  tag check_id: 'C-65770r1000751_chk'
  tag severity: 'medium'
  tag gid: 'V-261916'
  tag rid: 'SV-261916r1000981_rule'
  tag stig_id: 'CD16-00-006900'
  tag gtitle: 'SRG-APP-000342-DB-000302'
  tag fix_id: 'F-65678r1000752_fix'
  tag 'documentable'
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']

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
