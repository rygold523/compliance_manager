import base64
import hashlib

from pathlib import Path
from typing import Any
from uuid import uuid4

import winrm

from app.services.ssh_host_keys import configured_ssh_client


PUBLIC_KEY_PATH = Path(
    "/home/aivuln/.ssh/aivuln_remote_exec.pub"
)

WINDOWS_BOOTSTRAP_PATH = Path(
    "/app/scripts/bootstrap_windows_managed_target.ps1"
)

LINUX_COMMAND_DISPATCHER_PATH = Path(
    "/app/scripts/compliance_agent_command.py"
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

    if not LINUX_COMMAND_DISPATCHER_PATH.exists():
        return {
            "status": "failed",
            "output": [
                _command_result(
                    command="Load Linux command dispatcher",
                    exit_code=1,
                    stdout="",
                    stderr=(
                        "Missing Linux command dispatcher: "
                        f"{LINUX_COMMAND_DISPATCHER_PATH}"
                    ),
                )
            ],
        }

    dispatcher_b64 = base64.b64encode(
        LINUX_COMMAND_DISPATCHER_PATH.read_bytes()
    ).decode("ascii")
    sudoers_text = (
        "Defaults:compliance-agent !requiretty\n"
        "compliance-agent ALL=(root) NOPASSWD: "
        "/usr/local/sbin/compliance-agent-command *\n"
    )
    sudoers_b64 = base64.b64encode(
        sudoers_text.encode("utf-8")
    ).decode("ascii")

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
        "sudo install -d -o root -g root -m 0755 /usr/local/sbin",
        (
            f"printf '%s' '{dispatcher_b64}' | base64 -d | "
            "sudo tee /usr/local/sbin/.compliance-agent-command.new "
            ">/dev/null"
        ),
        (
            "sudo chown root:root "
            "/usr/local/sbin/.compliance-agent-command.new && "
            "sudo chmod 0755 "
            "/usr/local/sbin/.compliance-agent-command.new && "
            "sudo /usr/bin/python3 -m py_compile "
            "/usr/local/sbin/.compliance-agent-command.new && "
            "sudo mv -f /usr/local/sbin/.compliance-agent-command.new "
            "/usr/local/sbin/compliance-agent-command"
        ),
        (
            f"printf '%s' '{sudoers_b64}' | base64 -d | "
            "sudo tee /etc/sudoers.d/.compliance-agent.new >/dev/null"
        ),
        (
            "sudo chown root:root /etc/sudoers.d/.compliance-agent.new && "
            "sudo chmod 0440 /etc/sudoers.d/.compliance-agent.new && "
            "sudo visudo -cf /etc/sudoers.d/.compliance-agent.new && "
            "sudo mv -f /etc/sudoers.d/.compliance-agent.new "
            "/etc/sudoers.d/compliance-agent"
        ),
        (
            "sudo rm -f /etc/sudoers.d/compliance-agent-collectors && "
            "sudo visudo -cf /etc/sudoers"
        ),
        "hostname",
    ]

    client = configured_ssh_client()

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
    ingest_token: str,
    credential_id: str,
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
    bootstrap_length = len(bootstrap_bytes)
    bootstrap_sha256 = hashlib.sha256(
        bootstrap_bytes
    ).hexdigest().upper()

    safe_asset_id = _powershell_single_quote(
        asset_id
    )
    safe_backend_url = _powershell_single_quote(
        backend_url.rstrip("/")
    )
    safe_ingest_token = _powershell_single_quote(ingest_token)
    safe_credential_id = _powershell_single_quote(credential_id)

    remote_directory = (
        r"C:\ProgramData\ComplianceAgent"
    )
    remote_script_path = (
        remote_directory
        + r"\bootstrap_windows_managed_target.ps1"
    )
    remote_upload_path = (
        remote_directory
        + "\\bootstrap_windows_managed_target."
        + uuid4().hex
        + ".tmp.ps1"
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
        safe_upload_path = (
            _powershell_single_quote(
                remote_upload_path
            )
        )

        initialize_script = (
            "$ErrorActionPreference = 'Stop'; "
            "New-Item -ItemType Directory "
            f"-Force -Path '{safe_directory}' "
            "| Out-Null; "
            "[System.IO.File]::WriteAllBytes("
            f"'{safe_upload_path}', "
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
                f"'{safe_upload_path}', "
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

        verify_script = (
            "$ErrorActionPreference = 'Stop'; "
            f"$path = '{safe_upload_path}'; "
            "$file = Get-Item -LiteralPath $path; "
            "$hash = (Get-FileHash -LiteralPath $path "
            "-Algorithm SHA256).Hash; "
            f"if ($file.Length -ne {bootstrap_length}) {{ "
            "throw ('Bootstrap length mismatch: ' + "
            "$file.Length) }; "
            f"if ($hash -ne '{bootstrap_sha256}') {{ "
            "throw ('Bootstrap SHA256 mismatch: ' + "
            "$hash) }; "
            "Write-Output ('Length=' + $file.Length + "
            "' SHA256=' + $hash)"
        )

        if not run_step(
            session,
            "Verify Windows bootstrap upload",
            verify_script,
        ):
            return {
                "status": "failed",
                "output": output,
            }

        execute_script = (
            "$ErrorActionPreference = 'Stop'; "
            "& "
            f"'{safe_upload_path}' "
            f"-BackendUrl '{safe_backend_url}' "
            f"-AssetId '{safe_asset_id}' "
            f"-IngestToken '{safe_ingest_token}' "
            f"-CredentialId '{safe_credential_id}'"
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

        promote_script = (
            "$ErrorActionPreference = 'Stop'; "
            "[System.IO.File]::Copy("
            f"'{safe_upload_path}', "
            f"'{safe_script_path}', $true); "
            "Remove-Item -LiteralPath "
            f"'{safe_upload_path}' -Force"
        )

        if not run_step(
            session,
            "Finalize Windows bootstrap upload",
            promote_script,
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
    ingest_token: str = "",
    credential_id: str = "",
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

        if not ingest_token:
            return {
                "status": "failed",
                "output": [
                    _command_result(
                        command="Validate deployment",
                        exit_code=1,
                        stdout="",
                        stderr=(
                            "WINDOWS_AGENT_INGEST_TOKEN is required "
                            "for Windows deployment"
                        ),
                    )
                ],
            }

        if not credential_id:
            return {
                "status": "failed",
                "output": [
                    _command_result(
                        command="Validate deployment",
                        exit_code=1,
                        stdout="",
                        stderr="Windows agent credential ID is required",
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
            ingest_token=ingest_token,
            credential_id=credential_id,
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
