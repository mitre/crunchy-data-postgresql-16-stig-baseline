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
  desc 'check', 'Verify FIPS is enabled for the OS. Following are example Linux commands:

# sysctl crypto.fips_enabled
crypto.fips_enabled = 1

If crypto.fips_enabled = 0, this is a finding.

OR

$ sudo fips-mode-setup --check
FIPS mode is enabled.

If FIPS mode is not enabled, this is a finding.

Run the following command to check the OpenSSL version:

$ openssl -version

Note: FIPS-compliant libraries for OpenSSL 1.x.x contain "fips" in the version.

If the value of OpenSSL library is not FIPS compliant, this is a finding.

If using OpenSSL 3.x, check the providers:

openssl list -providers

Providers:
default
name: OpenSSL Default Provider
version: 3.2.2
status: active

fips
    name: Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider
    version: 3.2.2-622cc79c634cbbef
    status: active

If the response does not list a FIPS provider with a status of "active", this is a finding.'
  desc 'fix', 'If crypto.fips_enabled = 0 for Red Hat Linux, configure the operating system to implement DOD-approved encryption.

To enable strict FIPS compliance, the fips=1 kernel option must be added to the kernel command line during system installation so key generation is done with FIPS-approved algorithms and continuous monitoring tests in place.

Enable FIPS mode with the following command:

# sudo fips-mode-setup --enable

Modify the kernel command line of the current kernel in the "grub.cfg" file by adding the following option to the GRUB_CMDLINE_LINUX key in the "/etc/default/grub" file and then rebuilding the "grub.cfg" file:

fips=1

Changes to "/etc/default/grub" require rebuilding the "grub.cfg" file.

On BIOS-based machines, use the following command:

# sudo grub2-mkconfig -o /boot/grub2/grub.cfg

On UEFI-based machines, use the following command:

# sudo grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg

If /boot or /boot/efi reside on separate partitions, the kernel parameter "boot=<partition of /boot or /boot/efi>" must be added to the kernel command line. Identify a partition by running the df /boot or df /boot/efi command:

# sudo df /boot

Filesystem 1K-blocks Used Available Use% Mounted on
/dev/sda1 495844 53780 416464 12% /boot

To ensure the "boot=" configuration option will work even if device naming changes occur between boots, identify the universally unique identifier (UUID) of the partition with the following command:

# sudo blkid /dev/sda1
/dev/sda1: UUID="05c000f1-a213-759e-c7a2-f11b7424c797" TYPE="ext4"

For the example above, append the following string to the kernel command line:

boot=UUID=05c000f1-a213-759e-c7a2-f11b7424c797

Reboot the system for the changes to take effect.

More information can be found here:
RedHat: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-federal_standards_and_regulations
Ubuntu: https://security-certs.docs.ubuntu.com/en/fips

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

  describe command('openssl') do
    it { should exist }
  end

  # Check OS-level FIPS is enabled
  describe.one do
    describe command('sysctl crypto.fips_enabled') do
      its('stdout') { should match /crypto\.fips_enabled\s*=\s*1/ }
    end

    describe command('fips-mode-setup --check') do
      its('stdout') { should match /FIPS mode is enabled/i }
    end
  end

  # For OpenSSL 1.x: 'fips' appears in version string
  # For OpenSSL 3.x: a FIPS provider must be active
  describe.one do
    describe command('openssl list -providers') do
      its('stdout') { should match /^fips$(?:\n^[ \t]+.*$)*\n^[ \t]+status:\s*active$/m }
    end

    describe command('openssl version') do
      its('stdout') { should include 'fips' }
    end
  end
end
