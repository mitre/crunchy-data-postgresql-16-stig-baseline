control 'SV-261910' do
  title 'PostgreSQL must automatically terminate a user session after organization-defined conditions or
	trigger events requiring session disconnect.'
  desc "This addresses the termination of user-initiated logical sessions in contrast to the termination of
	network connections that are associated with communications sessions (i.e., network disconnect). A logical
	session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a
		user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate
			user access) without terminating network sessions.

Session termination ends all processes associated with a user's logical session except those batch processes/jobs
that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined
periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on
information system use.

This capability is typically reserved for specific cases where the system owner, data owner, or organization requires
additional assurance."
  desc 'check', "Review system documentation to obtain the organization's definition of circumstances requiring
	automatic session termination. If the documentation explicitly states that such termination is not required or
	is prohibited, this is not a finding.

If the documentation requires automatic session termination, but PostgreSQL is not configured accordingly, this is a
finding."
  desc 'fix', "Configure PostgreSQL to automatically terminate a user session after organization-defined conditions or trigger events requiring session termination.

Examples follow.

### Change a role to nologin and disconnect the user

ALTER ROLE '<username>' NOLOGIN;
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='<usename>';

### Disconnecting users during a specific time range
Refer to supplementary content APPENDIX-A for a bash script for this example.

The script found in APPENDIX-A using the -l command can disable all users with rolcanlogin=t from logging in. The script keeps track of who it disables in a .restore_login file. After the specified time is over, the same script can be run with the -r command to restore all login connections.

This script would be added to a cron job:

# lock at 5 am every day of the week, month, year at the 0 minute mark.
0 5 * * * postgres /var/lib/pgsql/no_login.sh -d postgres -l
# restore at 5 pm every day of the week, month, year at the 0 minute mark.
0 17 * * * postgres /var/lib/pgsql/no_login.sh -d postgres -r"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000295-DB-000305'
  tag gid: 'V-261910'
  tag rid: 'SV-261910r1000735_rule'
  tag stig_id: 'CD16-00-006200'
  tag fix_id: 'F-65672r1000734_fix'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']

  describe "Check if organization's definition of circumstances requiring automatic session termination is met" do
    skip 'If the documentation requires automatic session termination, but PostgreSQL is not configured accordingly, this is a finding'
  end
end
