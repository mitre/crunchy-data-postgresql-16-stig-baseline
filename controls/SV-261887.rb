control 'SV-261887' do
  title 'Unused database components that are integrated in PostgreSQL and cannot be uninstalled must be disabled.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives.

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.

Unused, unnecessary PostgreSQL components increase the attack vector for PostgreSQL by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced. Components of the system that are unused and cannot be uninstalled must be disabled. The techniques available for disabling components will vary by DBMS product, OS, and the nature of the component and may include PostgreSQL configuration settings, OS service settings, OS file access security, and PostgreSQL user/role permissions.'
  desc 'check', 'To list all installed packages, as the system administrator, run the following:

# RHEL/CENT 8/9 Systems
$ sudo dnf list installed | grep postgres

# RHEL/CENT 7 Systems
$ sudo yum list installed | grep postgres

# Debian Systems
$ dpkg --get-selections | grep postgres

If any of the packages installed not required, this is a finding.'
  desc 'fix', 'To remove any unneeded executables, as the system administrator, run the following:

# RHEL/CENT Systems
$ sudo yum erase <package_name>

# Debian Systems
$ sudo apt-get remove <package_name>'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag gid: 'V-261887'
  tag rid: 'SV-261887r1000666_rule'
  tag stig_id: 'CD16-00-003300'
  tag fix_id: 'F-65649r1000665_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']


  expected = input('approved_packages')
  actual = packages(/postgres/).names

  failing = actual - expected

  describe "The list of Postgres packages that were not in the allowlist" do
    subject {failing}
    it {should be_empty}
  end
end
