# AI Security Setup Scripts

Place these files in `scripts/` inside your `AI_Security` GitHub repository.

Fresh server install:

```bash
sudo chmod +x scripts/*.sh
sudo scripts/master_setup.sh
```

The scripts assume the backend/frontend application code already exists in the repository. The scripts do not rewrite application source code. They install the host, create the PostgreSQL container, configure Docker networking, generate `.env`, start the stack, apply schema compatibility updates, and validate the platform.
