# Phase 2: Linux least-privilege execution

This phase replaces broad Linux sudoers grants with a root-owned dispatcher.

## Security properties

- The compliance account may invoke only `/usr/local/sbin/compliance-agent-command` through sudo.
- The dispatcher accepts an explicit action allowlist and rejects extra arguments.
- Package names are validated before the existing package manager is invoked.
- Collector scripts must be regular files owned by root and not writable by group or others.
- `install_collectors.py` is never exposed as a runtime action.
- Authentication logs, SSH configuration, and firewall state use fixed paths and commands.
- The new sudoers file is checked with `visudo` before it replaces the existing policy.
- The legacy `compliance-agent-collectors` policy is removed only after the replacement is installed.

## Preserved functions

- IAM users
- Authentication successes, failures, user changes, and sudo activity
- OS, disk, Docker, listening-port, package, lifecycle, and collector-health inventory
- SSH and firewall configuration evidence
- Individual, held, non-held bulk, and including-held bulk package upgrades
- Agent removal

## Rollout

Deploy to `test_vm` first. Run all collectors and a package inventory check before migrating the remaining Linux assets. Do not test a real package update unless an approved update is available.
