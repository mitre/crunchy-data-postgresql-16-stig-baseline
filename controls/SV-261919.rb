control 'SV-261919' do
  title 'PostgreSQL must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75 percent of maximum audit record storage capacity.'
  desc 'Organizations are required to use a central log management system so under normal conditions, the audit space allocated to PostgreSQL on its own server will not be an issue. However, space will still be required on the PostgreSQL server for audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result.

If support personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion. 

The appropriate support staff include, at a minimum, the information system security officer (ISSO) and the database administrator (DBA)/system administrator (SA).'
  desc 'check', 'Review system configuration.

If no script or tool is monitoring the partition for the PostgreSQL log directories, this is a finding.

If appropriate support staff are not notified immediately upon storage volume utilization reaching 75 percent, this is a finding.'
  desc 'fix', %q(Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Configure the system to notify appropriate support staff immediately upon storage volume utilization reaching 75 percent.

PostgreSQL does not monitor storage; however, it is possible to monitor storage with a script.

##### Example Monitoring Script

#!/bin/bash

PGDATA=/var/lib/pgsql/${PGVER?}/data
CURRENT=$(df ${PGDATA?} | grep / | awk '{ print $5}' | sed 's/%//g')
THRESHOLD=75

if [ "$CURRENT" -gt "$THRESHOLD" ] ; then
mail -s 'Disk Space Alert' mail@support.com << EOF
The data directory volume is almost full. Used: $CURRENT
EOF
fi

Schedule this script in cron to run around the clock.)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag gid: 'V-261919'
  tag rid: 'SV-261919r1000762_rule'
  tag stig_id: 'CD16-00-007300'
  tag fix_id: 'F-65681r1000761_fix'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']

  describe 'Check system configuration for storage alerts.' do
    skip 'Review system configuration. If no script/tool is monitoring the partition for the PostgreSQL log directories, this is a finding.'
    skip 'If appropriate support staff are not notified immediately upon storage volume utilization reaching 75%, this is a finding'
  end
end
