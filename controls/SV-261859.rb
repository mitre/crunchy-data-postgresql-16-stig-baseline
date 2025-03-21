control 'SV-261859' do
  title 'PostgreSQL must enforce approved authorizations for logical access to information and system resources
	in accordance with applicable access control policies.'
  desc 'Authentication with a DOD-approved PKI certificate does not necessarily imply authorization to access PostgreSQL. To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DOD-approved PKIs, all DOD systems, including databases, must be properly configured to implement access control policies.

Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

This requirement is applicable to access control enforcement applications, a category that includes database management systems. If PostgreSQL does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy.'
  desc 'check', %q(Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

From the system security plan or equivalent documentation, determine the appropriate permissions on database objects for each kind (group role) of user. If this documentation is missing, this is a finding.

As the database administrator (shown here as "postgres"), check the privileges of all roles in the database by running the following SQL:

$ sudo su - postgres
$ psql -c '\du'

Review all roles and their associated privileges. If any roles' privileges exceed those documented, this is a finding.

As the database administrator (shown here as "postgres"), check the configured privileges for tables and columns by running the following SQL:

$ sudo su - postgres
$ psql -c '\dp'

Review all access privileges and column access privileges list. If any roles' privileges exceed those documented, this is a finding.

As the database administrator (shown here as "postgres"), check the configured authentication settings in pg_hba.conf:

$ sudo su - postgres
$ cat ${PGDATA?}/pg_hba.conf

Review all entries and their associated authentication methods. If any entries do not have their documented authentication requirements, this is a finding.)
  desc 'fix', %q(Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

Create and/or maintain documentation of each group role's appropriate permissions on database objects.

Implement these permissions in the database and remove any permissions that exceed those documented.

The following are examples of how to use role privileges in PostgreSQL to enforce access controls. For a complete list of privileges, refer to the official documentation: https://www.postgresql.org/docs/current/static/sql-createrole.html. 

#### Roles Example 1 

The following example demonstrates how to create an admin role with CREATEDB and CREATEROLE privileges. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "CREATE ROLE admin WITH CREATEDB CREATEROLE" 

#### Roles Example 2 

The following example demonstrates how to create a role with a password that expires and makes the role a member of the "admin" group. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "CREATE ROLE joe LOGIN ENCRYPTED PASSWORD 'stig_2024' VALID UNTIL '2024-09-20' IN ROLE admin" 

#### Roles Example 3 

The following demonstrates how to revoke privileges from a role using REVOKE. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "REVOKE admin FROM joe" 

#### Roles Example 4 

The following demonstrates how to alter privileges in a role using ALTER. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "ALTER ROLE joe NOLOGIN" 

The following are examples of how to use grant privileges in PostgreSQL to enforce access controls on objects. For a complete list of privileges, refer to the official documentation: https://www.postgresql.org/docs/current/static/sql-grant.html. 

#### Grant Example 1 

The following example demonstrates how to grant INSERT on a table to a role. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "GRANT SELECT ON stig_test TO joe" 

#### Grant Example 2 

The following example demonstrates how to grant ALL PRIVILEGES on a table to a role. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "GRANT ALL PRIVILEGES ON stig_test TO joe" 

#### Grant Example 3 

The following example demonstrates how to grant a role to a role. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "GRANT admin TO joe" 

#### Revoke Example 1 

The following example demonstrates how to revoke access from a role. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "REVOKE admin FROM joe" 

To change authentication requirements for the database, as the database administrator (shown here as "postgres"), edit pg_hba.conf: 

$ sudo su - postgres 

$ vi ${PGDATA?}/pg_hba.conf 

Edit authentication requirements to the organizational requirements. Refer to the official documentation for the complete list of options for authentication: http://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html. 

After changes to pg_hba.conf, reload the server: 

$ sudo systemctl reload postgresql-${PGVER?})
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag gid: 'V-261859'
  tag rid: 'SV-261859r1000582_rule'
  tag stig_id: 'CD16-00-000300'
  tag fix_id: 'F-65621r1000581_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  pg_replicas = input('pg_replicas')

  if input('windows_runner')
    describe 'Requires manual review at this time.' do
      skip 'Requires manual review at this time.'
    end
  else
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

    authorized_owners = input('pg_superusers')
    owners = authorized_owners.join('|')

    object_granted_privileges = 'arwdDxtU'
    object_public_privileges = 'r'
    object_acl = "^((((#{owners})=[#{object_granted_privileges}]+|"\
      "=[#{object_public_privileges}]+)\/\\w+,?)+|)\\|"
    object_acl_regex = Regexp.new(object_acl)

    objects_sql = 'SELECT n.nspname, c.relname, c.relkind '\
      'FROM pg_catalog.pg_class c '\
      'LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace '\
      "WHERE c.relkind IN ('r', 'v', 'm', 'S', 'f') "\
      "AND n.nspname !~ '^pg_' AND pg_catalog.pg_table_is_visible(c.oid);"

    databases_sql = 'SELECT datname FROM pg_catalog.pg_database where not datistemplate;'
    databases_query = sql.query(databases_sql, [input('pg_db')])
    databases = databases_query.lines

    databases.each do |database|
      rows = sql.query(objects_sql, [database])
      next unless rows.methods.include?(:output) # Handle connection disabled on database

      objects = rows.lines

      objects.each do |obj|
        schema, object, type = obj.split('|')
        relacl_sql = "SELECT pg_catalog.array_to_string(c.relacl, E','), "\
          'n.nspname, c.relname, c.relkind FROM pg_catalog.pg_class c '\
          'LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace '\
          "WHERE n.nspname = '#{schema}' AND c.relname = '#{object}' "\
          "AND c.relkind = '#{type}';"

        describe sql.query(relacl_sql, [database]) do
          its('output') { should match object_acl_regex }
        end
      end
    end

    describe 'Column acl check' do
      skip "Review all access privileges and column access privileges list. If any roles'
		privileges exceed those documented, this is a finding."
    end

    describe postgres_hba_conf(input('pg_hba_conf_file')).where { type == 'local' } do
      its('user.uniq') { should cmp input('pg_owner') }
      its('auth_method.uniq') { should_not cmp 'trust' }
    end

    describe postgres_hba_conf(input('pg_hba_conf_file')).where { database == 'replication' } do
      its('type.uniq') { should cmp 'host' }
      its('address.uniq.sort') { should cmp pg_replicas.sort }
      its('user.uniq') { should cmp 'replication' }
      its('auth_method.uniq') { should be_in input('approved_auth_methods') }
    end

    describe postgres_hba_conf(input('pg_hba_conf_file')).where { type == 'host' } do
      its('auth_method.uniq') { should be_in input('approved_auth_methods') }
    end
  end
end
