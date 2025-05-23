control 'SV-261883' do
  title 'Database software, including PostgreSQL configuration files, must be stored in dedicated directories, or DASD pools, separate from the host OS and other applications.'
  desc "When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens and is threatened by other hosted applications. Access controls defined for one application may by default provide access to the other application's database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications."
  desc 'check', 'Review the PostgreSQL software library directory and any subdirectories.

If any non-PostgreSQL software directories exist on the disk directory, examine or investigate their use. If any
of the directories are used by other applications, including third-party applications that use the PostgreSQL, this
is a finding.

Only applications that are required for the functioning and administration, not use, of the PostgreSQL software
library should be located in the same disk directory as the PostgreSQL software libraries.

If other applications are located in the same directory as PostgreSQL, this is a finding.'
  desc 'fix', 'Install all applications on directories separate from the PostgreSQL software library directory.
	Relocate any directories or reinstall other application software that currently shares the PostgreSQL software
	library directory.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000199'
  tag gid: 'V-261883'
  tag rid: 'SV-261883r1000654_rule'
  tag stig_id: 'CD16-00-002800'
  tag fix_id: 'F-65645r1000653_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  input('pg_shared_dirs').each do |dir|
    describe directory(dir) do
      it { should be_directory }
      it { should be_owned_by 'root' }
      it { should be_grouped_into 'root' }
      its('mode') { should cmp '0755' }
    end
    if virtualization.system == 'docker'
      describe 'If any non-PostgreSQL software directories exist on the disk directory, examine or investigate their use.' do
        skip 'If this directory is used by other applications, including third-party applications that use the PostgreSQL, this is a finding.'
      end

    else
      describe command("lsof | awk '$9 ~ \"#{dir}\" {print $1}'") do
        its('stdout') { should match /^$|postgres|postmaste/ }
        its('stderr') { should eq '' }
      end
    end
  end
end
