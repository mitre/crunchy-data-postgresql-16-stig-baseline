control 'SV-261896' do
  title 'PostgreSQL must use NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of using encryption and digital signatures to protect data. Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality, or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of PostgreSQL.

Applications (including DBMSs) using cryptography are required to use approved NIST FIPS 140-2 or 140-3 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

The standard for validating cryptographic modules will transition to the NIST FIPS 140-3 publication.

FIPS 140-2 modules can remain active for up to five years after validation or until September 21, 2026, when the FIPS 140-2 validations will be moved to the historical list. Even on the historical list, CMVP supports the purchase and use of these modules for existing systems. While federal agencies decide when they move to FIPS 140-3 only modules, purchasers are reminded that for several years there may be a limited selection of FIPS 140-3 modules from which to choose. CMVP recommends purchasers consider all modules that appear on the Validated Modules Search Page:
https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules.

More information on the FIPS 140-3 transition can be found here: 
https://csrc.nist.gov/Projects/fips-140-3-transition-effort/.'
  desc 'check', 'As the system administrator, run the following:

$ openssl version

If "fips" is not included in the OpenSSL version, this is a finding.'
  desc 'fix', 'Configure OpenSSL to meet FIPS Compliance using the following documentation in section 9.1: http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140sp/140sp1758.pdf.

For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag gid: 'V-261896'
  tag rid: 'SV-261896r1000693_rule'
  tag stig_id: 'CD16-00-004400'
  tag fix_id: 'F-65658r1000692_fix'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']

  describe command('openssl') do
    it { should exist }
  end

  describe command('openssl version') do
    its('stdout') { should include 'fips' }
  end
end
