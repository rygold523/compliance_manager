import base64

from pathlib import Path
from typing import Any

import paramiko
import winrm


PUBLIC_KEY_PATH = Path(
    "/home/aivuln/.ssh/aivuln_remote_exec.pub"
)

WINDOWS_BOOTSTRAP_PATH = Path(
    "/app/scripts/bootstrap_windows_managed_target.ps1"
)


def get_public_key() -> str:
    if not PUBLIC_KEY_PATH.exists():
        raise FileNotFoundError(
            f"Missing public key: {PUBLIC_KEY_PATH}"
        )

    return PUBLIC_KEY_PATH.read_text(
        encoding="utf-8"
    ).strip()


def _command_result(
    command: str,
    exit_code: int,
    stdout: str,
    stderr: str,
) -> dict[str, Any]:
    return {
        "command": command[:120],
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
    }


def _powershell_single_quote(value: str) -> str:
    return value.replace("'", "''")


def deploy_linux_agent(
    address: str,
    username: str,
    password: str,
    port: int,
) -> dict:
    public_key = get_public_key()

    commands = [
        (
            "sudo useradd -m -s /bin/bash "
            "compliance-agent 2>/dev/null || true"
        ),
        (
            "sudo mkdir -p "
            "/home/compliance-agent/.ssh"
        ),
        (
            f"echo '{public_key}' | sudo tee -a "
            "/home/compliance-agent/.ssh/"
            "authorized_keys >/dev/null"
        ),
        (
            "sudo sort -u "
            "/home/compliance-agent/.ssh/"
            "authorized_keys -o "
            "/home/compliance-agent/.ssh/"
            "authorized_keys"
        ),
        (
            "sudo chown -R "
            "compliance-agent:compliance-agent "
            "/home/compliance-agent/.ssh"
        ),
        (
            "sudo chmod 700 "
            "/home/compliance-agent/.ssh"
        ),
        (
            "sudo chmod 600 "
            "/home/compliance-agent/.ssh/"
            "authorized_keys"
        ),
        """cat <<'EOF' | sudo tee /etc/sudoers.d/compliance-agent >/dev/null
compliance-agent ALL=(root) NOPASSWD: /usr/bin/hostnamectl, /usr/bin/lsb_release, /usr/bin/uname, /usr/bin/uptime, /usr/bin/df, /usr/bin/free, /usr/bin/ip, /usr/bin/ss
compliance-agent ALL=(root) NOPASSWD: /usr/bin/apt-mark, /usr/bin/apt-cache, /usr/bin/apt, /usr/bin/apt-get, /usr/bin/dpkg, /usr/bin/timedatectl
compliance-agent ALL=(root) NOPASSWD: /usr/sbin/nginx, /bin/systemctl status nginx, /bin/systemctl reload nginx
compliance-agent ALL=(root) NOPASSWD: /usr/bin/journalctl, /usr/bin/tail, /usr/bin/grep, /usr/bin/zgrep, /usr/bin/find, /usr/bin/cat
compliance-agent ALL=(root) NOPASSWD: /usr/sbin/ufw status, /usr/sbin/ufw status verbose, /usr/sbin/nft list ruleset, /usr/sbin/iptables -S, /usr/bin/docker ps
EOF""",
        (
            "sudo chmod 440 "
            "/etc/sudoers.d/compliance-agent"
        ),
        (
            "sudo visudo -cf "
            "/etc/sudoers.d/compliance-agent"
        ),
        "hostname",
    ]

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    output = []

    try:
        client.connect(
            hostname=address,
            port=port,
            username=username,
            password=password,
            timeout=20,
            banner_timeout=30,
            auth_timeout=30,
        )

        for command in commands:
            _, stdout, stderr = client.exec_command(
                command,
                timeout=60,
            )
            exit_code = stdout.channel.recv_exit_status()

            result = _command_result(
                command=command,
                exit_code=exit_code,
                stdout=stdout.read().decode(
                    errors="replace"
                ),
                stderr=stderr.read().decode(
                    errors="replace"
                ),
            )
            output.append(result)

            if exit_code != 0:
                return {
                    "status": "failed",
                    "output": output,
                }

        return {
            "status": "deployed",
            "output": output,
        }

    except Exception as exc:
        output.append(
            _command_result(
                command="Connect using SSH",
                exit_code=1,
                stdout="",
                stderr=str(exc),
            )
        )
        return {
            "status": "failed",
            "output": output,
        }

    finally:
        client.close()


def deploy_windows_agent(
    address: str,
    username: str,
    password: str,
    port: int,
    asset_id: str,
    backend_url: str,
) -> dict:
    if not WINDOWS_BOOTSTRAP_PATH.exists():
        return {
            "status": "failed",
            "output": [
                _command_result(
                    command=(
                        "Load Windows bootstrap script"
                    ),
                    exit_code=1,
                    stdout="",
                    stderr=(
                        "Missing Windows bootstrap script: "
                        f"{WINDOWS_BOOTSTRAP_PATH}"
                    ),
                )
            ],
        }

    bootstrap_bytes = (
        WINDOWS_BOOTSTRAP_PATH.read_bytes()
    )

    safe_asset_id = _powershell_single_quote(
        asset_id
    )
    safe_backend_url = _powershell_single_quote(
        backend_url.rstrip("/")
    )

    remote_directory = (
        r"C:\ProgramData\ComplianceAgent"
    )
    remote_script_path = (
        remote_directory
        + r"\bootstrap_windows_managed_target.ps1"
    )

    endpoint = (
        f"http://{address}:{port}/wsman"
    )

    output = []

    def run_step(
        session,
        command_name: str,
        script: str,
    ) -> bool:
        result = session.run_ps(script)

        stdout = result.std_out.decode(
            errors="replace"
        )
        stderr = result.std_err.decode(
            errors="replace"
        )

        output.append(
            _command_result(
                command=command_name,
                exit_code=result.status_code,
                stdout=stdout,
                stderr=stderr,
            )
        )

        return result.status_code == 0

    try:
        session = winrm.Session(
            endpoint,
            auth=(username, password),
            transport="ntlm",
            server_cert_validation="ignore",
            operation_timeout_sec=120,
            read_timeout_sec=150,
        )

        safe_directory = (
            _powershell_single_quote(
                remote_directory
            )
        )
        safe_script_path = (
            _powershell_single_quote(
                remote_script_path
            )
        )

        initialize_script = (
            "$ErrorActionPreference = 'Stop'; "
            "New-Item -ItemType Directory "
            f"-Force -Path '{safe_directory}' "
            "| Out-Null; "
            "[System.IO.File]::WriteAllBytes("
            f"'{safe_script_path}', "
            "[byte[]]@())"
        )

        if not run_step(
            session,
            "Initialize Windows bootstrap upload",
            initialize_script,
        ):
            return {
                "status": "failed",
                "output": output,
            }

        chunk_size = 1500

        for offset in range(
            0,
            len(bootstrap_bytes),
            chunk_size,
        ):
            chunk = bootstrap_bytes[
                offset:offset + chunk_size
            ]
            encoded_chunk = (
                base64.b64encode(chunk).decode(
                    "ascii"
                )
            )

            append_script = (
                "$ErrorActionPreference = 'Stop'; "
                "$bytes = "
                "[System.Convert]::FromBase64String("
                f"'{encoded_chunk}'); "
                "$stream = "
                "[System.IO.File]::Open("
                f"'{safe_script_path}', "
                "[System.IO.FileMode]::Append, "
                "[System.IO.FileAccess]::Write, "
                "[System.IO.FileShare]::None); "
                "try { "
                "$stream.Write("
                "$bytes, 0, $bytes.Length"
                ") "
                "} finally { "
                "$stream.Dispose() "
                "}"
            )

            chunk_number = (
                offset // chunk_size
            ) + 1

            if not run_step(
                session,
                (
                    "Upload Windows bootstrap "
                    f"chunk {chunk_number}"
                ),
                append_script,
            ):
                return {
                    "status": "failed",
                    "output": output,
                }

        execute_script = (
            "$ErrorActionPreference = 'Stop'; "
            "& "
            f"'{safe_script_path}' "
            f"-BackendUrl '{safe_backend_url}' "
            f"-AssetId '{safe_asset_id}'"
        )

        if not run_step(
            session,
            "Execute Windows bootstrap script",
            execute_script,
        ):
            return {
                "status": "failed",
                "output": output,
            }

        return {
            "status": "deployed",
            "output": output,
        }

    except Exception as exc:
        output.append(
            _command_result(
                command="Connect using WinRM",
                exit_code=1,
                stdout="",
                stderr=str(exc),
            )
        )

        return {
            "status": "failed",
            "output": output,
        }


def deploy_agent(
    address: str,
    username: str,
    password: str,
    port: int = 22,
    os_family: str = "ubuntu",
    asset_id: str = "",
    backend_url: str = "",
) -> dict:
    normalized_os = os_family.strip().lower()

    if normalized_os == "windows":
        if not asset_id:
            return {
                "status": "failed",
                "output": [
                    _command_result(
                        command="Validate deployment",
                        exit_code=1,
                        stdout="",
                        stderr=(
                            "asset_id is required for "
                            "Windows deployment"
                        ),
                    )
                ],
            }

        if not backend_url:
            return {
                "status": "failed",
                "output": [
                    _command_result(
                        command="Validate deployment",
                        exit_code=1,
                        stdout="",
                        stderr=(
                            "PUBLIC_BACKEND_URL is required "
                            "for Windows deployment"
                        ),
                    )
                ],
            }

        return deploy_windows_agent(
            address=address,
            username=username,
            password=password,
            port=port,
            asset_id=asset_id,
            backend_url=backend_url,
        )

    if normalized_os in {
        "linux",
        "ubuntu",
        "debian",
    }:
        return deploy_linux_agent(
            address=address,
            username=username,
            password=password,
            port=port,
        )

    return {
        "status": "failed",
        "output": [
            _command_result(
                command="Validate operating system",
                exit_code=1,
                stdout="",
                stderr=(
                    "Unsupported operating system: "
                    f"{os_family}"
                ),
            )
        ],
    }
