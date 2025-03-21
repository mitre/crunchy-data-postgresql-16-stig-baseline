control 'SV-261937' do
  title 'PostgreSQL products must be a version supported by the vendor.'
  desc 'Unsupported commercial and database systems should not be used because fixes to newly identified bugs will not be implemented by the vendor. The lack of support can result in potential vulnerabilities.

Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

When maintenance updates and patches are no longer available, the database software is no longer considered supported and should be upgraded or decommissioned.'
  desc 'check', 'If new packages are available for PostgreSQL, they can be reviewed in the package manager appropriate for the server operating system:

To list the version of installed PostgreSQL using psql:

$ sudo su - postgres
$ psql --version

To list the current version of software for RPM:

$ rpm -qa | grep postgres

To list the current version of software for APT:

$ apt-cache policy postgres

All versions of PostgreSQL are listed here: http://www.postgresql.org/support/versioning/

All security-relevant software updates for PostgreSQL are listed here: http://www.postgresql.org/support/security/

If PostgreSQL is not at the latest version, this is a finding.

If PostgreSQL is not at the latest version and the evaluated version has CVEs (IAVAs), this is a CAT I finding.'
  desc 'fix', 'Institute and adhere to policies and procedures to ensure that patches are consistently applied to PostgreSQL within the time allowed.'
  impact 0.7
  tag check_id: 'C-65791r1000974_chk'
  tag severity: 'high'
  tag gid: 'V-261937'
  tag rid: 'SV-261937r1000974_rule'
  tag stig_id: 'CD16-00-009300'
  tag gtitle: 'SRG-APP-000456-DB-000400'
  tag fix_id: 'F-65699r1000815_fix'
  tag 'documentable'
  tag cci: ['CCI-003376']
  tag nist: ['SA-22 a']

  min_org_allowed_postgres_version = input('min_org_allowed_postgres_version')
  installed_postgres_version = command('psql --version').stdout.split[2]

  # If no organization specified postgres version was given, check the internet for major and minor release versions
  if (min_org_allowed_postgres_version.nil? || min_org_allowed_postgres_version.empty?)
    describe "Your installed Postgres version is: #{installed_postgres_version}. You must review this control manually or set / pass the 'min_org_allowed_postgres_version' to the profile. The latest supported releases can be found at http://www.postgresql.org/support/versioning/" do
      skip "Your installed Postgres version is: #{installed_postgres_version}. You must review this control manually or set / pass the 'min_org_allowed_postgres_version' to the profile. The latest supported releases can be found at http://www.postgresql.org/support/versioning/"
    end
  else
    describe 'PostgreSQL installed version' do
      subject { installed_postgres_version }
      it { should cmp >= min_org_allowed_postgres_version }
    end
  end
end
