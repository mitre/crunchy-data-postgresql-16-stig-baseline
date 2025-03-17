control 'SV-261873' do
  title 'PostgreSQL must, by default, shut down upon audit failure, to include the unavailability of space for more audit log records; or must be configurable to shut down upon audit failure.'
  desc 'It is critical that when the DBMS is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

When the need for system availability does not outweigh the need for a complete audit trail, PostgreSQL should shut down immediately, rolling back all in-flight transactions.

Systems where audit trail completeness is paramount will most likely be at a lower MAC level than MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. In any case, sufficient auditing resources must be allocated to avoid a shutdown in all but the most extreme situations.'
  desc 'check', 'If the application owner has determined that the need for system availability outweighs the need for a complete audit trail, this is Not Applicable.

Review the procedures, either manually and/or automated, for monitoring the space used by audit trail(s) and for offloading audit records to a centralized log management system.

If the procedures do not exist, this is a finding.

If the procedures exist, request evidence that they are followed. If the evidence indicates that the procedures are not followed, this is a finding.

If the procedures exist, inquire if the system has ever run out of audit trail space in the last two years or since the last system upgrade, whichever is more recent. If it has run out of space in this period, and the procedures have not been updated to compensate, this is a finding.'
  desc 'fix', 'Modify PostgreSQL, OS, or third-party logging application settings to alert appropriate personnel when a specific percentage of log storage capacity is reached.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000109-DB-000049'
  tag gid: 'V-261873'
  tag rid: 'SV-261873r1000624_rule'
  tag stig_id: 'CD16-00-001700'
  tag fix_id: 'F-65635r1000623_fix'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']

  describe 'Check that PostgreSQL will shutdown upon audit failure.' do
    skip 'If PostgreSQL does not shut down upon audit failure or is not configurable to, this is a finding.'
  end
end
