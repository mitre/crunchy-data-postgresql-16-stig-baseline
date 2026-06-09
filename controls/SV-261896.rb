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
  tag rid: 'SV-261896r1193213_rule'
  tag stig_id: 'CD16-00-004400'
  tag fix_id: 'F-65658r1193212_fix'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']

  sysctl_exists          = command('sysctl').exist?
  fips_mode_setup_exists = command('fips-mode-setup').exist?
  openssl_exists         = command('openssl').exist?

  if sysctl_exists || fips_mode_setup_exists
    # Check OS-level FIPS using whichever tool is available.
    # sysctl is preferred because it does not require elevated privileges.
    # fips-mode-setup requires sudo — ensure 'inspec exec' is run with --sudo.
    if sysctl_exists
      describe command('sysctl crypto.fips_enabled') do
        its('stdout') { should match(/crypto\.fips_enabled\s*=\s*1/) }
      end
    else
      describe command('fips-mode-setup --check') do
        its('stdout') { should include 'FIPS mode is enabled' }
      end
    end

    # Check that the OpenSSL library is FIPS-compliant.
    # Verification method differs by version because OpenSSL changed its FIPS
    # architecture between 1.x (built-in, reported in version string) and 3.x
    # (separate provider model). OpenSSL 4.x has no documented FIPS check yet.
    if openssl_exists
      openssl_version = command('openssl version').stdout

      if openssl_version.match?(/OpenSSL 1\./)
        # OpenSSL 1.x includes 'fips' directly in the version string when
        # built with FIPS support.
        describe command('openssl version') do
          its('stdout') { should include 'fips' }
        end
      elsif openssl_version.match?(/OpenSSL 3\./)
        # OpenSSL 3.x uses a provider model; a FIPS provider must be listed
        # and have a status of 'active'.
        describe command('openssl list -providers') do
          its('stdout') { should match(/fips[\s\S]*?status: active/) }
        end
      else
        # OpenSSL 4.x or an unrecognized version — no documented FIPS
        # verification method exists yet. Manual review required.
        describe 'OpenSSL FIPS compliance' do
          skip "Manual review required: OpenSSL version '#{openssl_version.strip}' is not 1.x or 3.x. " \
               'No documented automated method exists for verifying FIPS compliance on this version. ' \
               'Verify manually that the installed OpenSSL is FIPS 140-2/140-3 approved.'
        end
      end
    else
      # OpenSSL is not present. Another FIPS-validated cryptographic module
      # may be in use — this cannot be verified automatically.
      describe 'OpenSSL FIPS compliance' do
        skip 'Manual review required: OpenSSL is not installed. ' \
             'Verify manually that a FIPS 140-2/140-3 validated cryptographic module is installed and active.'
      end
    end
  else
    # Neither sysctl nor fips-mode-setup is available, which means this is
    # likely a non-Linux system. FIPS status cannot be checked automatically.
    describe 'FIPS enablement' do
      skip 'Manual review required: Neither sysctl nor fips-mode-setup is available on this system. ' \
           'Verify manually that FIPS 140-2/140-3 validated cryptographic modules are enabled.'
    end
  end
end
