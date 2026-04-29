# Compliance Manager

Compliance Manager is a defensive compliance evidence and vulnerability management platform.

It provides:

- Central web GUI
- Managed agent deployment over SSH
- Evidence collectors
- Evidence-to-control mapping
- Findings segmented by PCI DSS, SOC 2, NIST 800-53, ISO 27001, and ISO 27002
- Compliance readiness scores
- PDF readiness reports
- Scanner ingestion foundation
- Optional local Ollama AI support, disabled by default

## Quick Start

On a fresh Ubuntu server:

```bash
sudo chmod +x scripts/*.sh
sudo scripts/master_setup.sh
```

Default application paths:

```text
/opt/ai-vulnerability-management
/var/lib/ai-vulnerability-management/evidence
/var/log/ai-vulnerability-management
```

Default ports:

```text
Frontend: 3000
Backend API: 8000
PostgreSQL: bound to 127.0.0.1:5432
```

## Important

This is an MVP. Before real production use, add:

- TLS
- Authentication
- Role-based access control
- Formal database migrations
- Hardened secret management
- Backup scheduling
