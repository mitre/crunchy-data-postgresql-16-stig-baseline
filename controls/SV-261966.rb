control 'SV-261966' do
  title "PostgreSQL must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the data owners' requirements."
  desc "Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

For detailed information, refer to NIST FIPS Publication 140-3, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS compliant."
  desc 'check', 'As the system administrator, run the following to ensure FIPS is enabled:

$ cat /proc/sys/crypto/fips_enabled

If fips_enabled is not "1", this is a finding.'
  desc 'fix', 'Configure OpenSSL to be FIPS compliant.

PostgreSQL uses OpenSSL for cryptographic modules. To configure OpenSSL to be FIPS 140-2 compliant, refer to the official RHEL Documentation: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening#switching-the-system-to-fips-mode_using-the-system-wide-cryptographic-policies.

For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000514-DB-000383'
  tag gid: 'V-261966'
  tag rid: 'SV-261966r1000965_rule'
  tag stig_id: 'CD16-00-012300'
  tag fix_id: 'F-65728r1000902_fix'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13', 'SC-13 b']

  describe kernel_parameter('crypto.fips_enabled') do
    its('value') { should cmp 1 }
  end
end
