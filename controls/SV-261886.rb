control 'SV-261886' do
  title 'Unused database components, PostgreSQL software, and database objects must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the
	functions and services, provided by default, may not be necessary to support essential organizational operations
	(e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or
mission objectives.

PostgreSQL must adhere to the principles of least functionality by providing only essential capabilities.'
  desc 'check', %q(To get a list of all extensions installed, use the following commands:

$ sudo su - postgres
$ psql -c "select * from pg_extension where extname != 'plpgsql'"

If any extensions exist that are not approved, this is a finding.)
  desc 'fix', 'To remove extensions, use the following commands:

$ sudo su - postgres
$ psql -c "DROP EXTENSION <extension_name>"

Note: Removal of plpgsql is not recommended.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag gid: 'V-261886'
  tag rid: 'SV-261886r1000951_rule'
  tag stig_id: 'CD16-00-003200'
  tag fix_id: 'F-65648r1000951_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  installed_extensions = sql.query("select extname from pg_extension where extname != 'plpgsql';").lines

  if installed_extensions.empty? || installed_extensions[0].strip==""
    installed_extensions=""
    describe 'The list of installed extensions' do
      subject { installed_extensions }
      it { should be_empty }
    end
  else
    installed_extensions.each do |extension|
      describe "The installed extension: #{extension}" do
        subject { extension }
        it { should be_in input('approved_ext') }
      end
    end
  end
end
