import paramiko
from pathlib import Path

PUBLIC_KEY_PATH = "/home/aivuln/.ssh/aivuln_remote_exec.pub"


def get_public_key() -> str:
    path = Path(PUBLIC_KEY_PATH)
    if not path.exists():
        raise FileNotFoundError(f"Missing public key: {PUBLIC_KEY_PATH}")
    return path.read_text().strip()


def deploy_agent(address: str, username: str, password: str, port: int = 22) -> dict:
    public_key = get_public_key()

    commands = [
        "sudo useradd -m -s /bin/bash compliance-agent 2>/dev/null || true",
        "sudo mkdir -p /home/compliance-agent/.ssh",
        f"echo '{public_key}' | sudo tee -a /home/compliance-agent/.ssh/authorized_keys >/dev/null",
        "sudo sort -u /home/compliance-agent/.ssh/authorized_keys -o /home/compliance-agent/.ssh/authorized_keys",
        "sudo chown -R compliance-agent:compliance-agent /home/compliance-agent/.ssh",
        "sudo chmod 700 /home/compliance-agent/.ssh",
        "sudo chmod 600 /home/compliance-agent/.ssh/authorized_keys",
        '''cat <<'EOF' | sudo tee /etc/sudoers.d/compliance-agent >/dev/null
compliance-agent ALL=(root) NOPASSWD: /usr/bin/hostnamectl, /usr/bin/lsb_release, /usr/bin/uname, /usr/bin/uptime, /usr/bin/df, /usr/bin/free, /usr/bin/ip, /usr/bin/ss
compliance-agent ALL=(root) NOPASSWD: /usr/bin/apt-mark, /usr/bin/apt-cache, /usr/bin/apt, /usr/bin/apt-get, /usr/bin/dpkg, /usr/bin/timedatectl
compliance-agent ALL=(root) NOPASSWD: /usr/sbin/nginx, /bin/systemctl status nginx, /bin/systemctl reload nginx
compliance-agent ALL=(root) NOPASSWD: /usr/bin/journalctl, /usr/bin/tail, /usr/bin/grep, /usr/bin/zgrep, /usr/bin/find, /usr/bin/cat
compliance-agent ALL=(root) NOPASSWD: /usr/sbin/ufw status, /usr/bin/docker ps
EOF''',
        "sudo chmod 440 /etc/sudoers.d/compliance-agent",
        "sudo visudo -cf /etc/sudoers.d/compliance-agent",
        "hostname",
    ]

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=address, port=port, username=username, password=password, timeout=20, banner_timeout=30, auth_timeout=30)

    output = []
    for command in commands:
        stdin, stdout, stderr = client.exec_command(command, timeout=60)
        exit_code = stdout.channel.recv_exit_status()
        output.append({
            "command": command[:120],
            "exit_code": exit_code,
            "stdout": stdout.read().decode(errors="replace"),
            "stderr": stderr.read().decode(errors="replace"),
        })
        if exit_code != 0:
            client.close()
            return {"status": "failed", "output": output}

    client.close()
    return {"status": "deployed", "output": output}
