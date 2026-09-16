from pathlib import Path

import paramiko

from app.core.config import settings


def configured_ssh_client() -> paramiko.SSHClient:
    """Create an SSH client that persists first-seen keys and rejects changes."""
    known_hosts = Path(settings.ssh_known_hosts_file)
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    known_hosts.touch(mode=0o600, exist_ok=True)
    known_hosts.chmod(0o600)

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.load_host_keys(str(known_hosts))
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return client
