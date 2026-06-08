# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a MITRE SAF InSpec profile that validates Crunchy Data PostgreSQL 16 against the DISA STIG (Security Technical Implementation Guide). It contains 111 automated security controls (SV-261857 through SV-261967) that run SQL queries, shell commands, and file checks against a target PostgreSQL 16 instance to assess compliance.

- **Profile Version:** 1.1.0
- **Benchmark:** Crunchy Data PostgreSQL 16 STIG V1R1 (13 Jun 2024)
- **InSpec version:** >= 4.0
- **Runtime:** CINC Auditor (open-source InSpec) or Chef InSpec

## Commands

```bash
# Install dependencies
bundle install

# Validate the profile (syntax/structure check)
bundle exec rake inspec:check
# or directly:
bundle exec cinc-auditor check .

# Lint controls
bundle exec rake lint
bundle exec rake lint:auto_correct

# Pre-commit checks (lint + profile validation)
bundle exec rake pre_commit_checks

# Start a local test PostgreSQL 16 container
docker compose up -d

# Run the profile against a target database
inspec exec ./ --input-file ./inputs_postgres16_example.yml --reporter cli json:./results/file.json

# Run from remote
bundle exec cinc-auditor exec https://github.com/mitre/crunchy-data-postgresql-16-stig-baseline/archive/main.tar.gz \
  --input-file=<your_inputs_file.yml> --reporter=cli json:<your_results_file.json>
```

## Architecture

### Control Files (`controls/SV-*.rb`)

Each file implements one STIG control. Controls follow a standard structure:

```ruby
control 'SV-XXXXXX' do
  title '...'
  desc '...'              # Vulnerability discussion
  desc 'check', '...'     # Manual check procedure from the STIG
  desc 'fix', '...'       # Manual fix procedure from the STIG
  impact 0.5              # 0.7 = high, 0.5 = medium, 0.3 = low
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-...'
  tag gid: 'V-XXXXXX'
  tag rid: 'SV-XXXXXXrN_rule'
  tag stig_id: 'CD16-00-XXXXXX'
  tag cci: ['CCI-XXXXXX']
  tag nist: ['XX-X']

  # Test implementation using InSpec resources
end
```

### Common Test Patterns in Controls

**SQL queries via `postgres_session`** (~77 controls): The most common pattern. Creates a session and runs SQL against the target database:
```ruby
sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))
describe sql.query('SHOW ssl;', [input('pg_db')]) do
  its('output') { should eq 'on' }
end
```

**Shell commands** (~27 controls): For OS-level checks (FIPS mode, file permissions, installed packages):
```ruby
describe command('openssl version') do
  its('stdout') { should include 'fips' }
end
```

**File/directory checks** (~22 file, ~9 directory): Verify config file permissions and ownership:
```ruby
describe file(input('pg_conf_file')) do
  its('mode') { should cmp '0600' }
  its('owner') { should eq input('pg_owner') }
end
```

**Windows runner guard**: Two controls (SV-261859, SV-261885) branch on `input('windows_runner')` for platform-specific logic.

**Manual review skips**: ~44 controls include `skip` blocks for checks that cannot be fully automated and require manual verification.

### Inputs (`inspec.yml`)

All configurable parameters are defined in `inspec.yml` with defaults. Key connection inputs that must be overridden for any real target:
- `pg_dba` / `pg_dba_password` — DBA credentials
- `pg_host` / `pg_port` / `pg_db` — connection info
- `pg_version` — must match the target (default: `16.9`)

Path inputs default to RHEL/CentOS layout (`/var/lib/pgsql/16/data/`). The example input file (`inputs_postgres16_example.yml`) uses Debian/Ubuntu paths (`/var/lib/postgresql/data/`). Override these per your target OS.

### Helper Library (`libraries/helper_methods.rb`)

Provides a `CustomHelpers` module with `report_result` — a helper for structured test output that wraps assertions with OK/FAILED reporting. Included globally via `Inspec::ProfileContext`.

### Local Test Environment (`docker-compose.yml` + `init.sql`)

A minimal PostgreSQL 16 container with user `testuser`/`testpassword` and database `testdb`. The `init.sql` seeds a simple `users` table. Use `inputs_postgres16_example.yml` to run the profile against this container.

## RuboCop Configuration

The `.rubocop.yml` is tuned for InSpec profiles:
- `Layout/LineLength` max 1500 (STIG descriptions are long)
- `Metrics/BlockLength` max 1000 (controls are large blocks)
- `Naming/FileName` disabled (control files are named `SV-XXXXXX.rb`)
- `Style/NumericPredicate` disabled (required to avoid InSpec profile errors)
- `libraries/` is excluded from linting
