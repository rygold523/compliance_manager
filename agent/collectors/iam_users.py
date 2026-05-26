#!/usr/bin/env python3
import json
import os
import pwd
import grp
import socket
from datetime import datetime, timezone

NORMAL_UID_MIN = 1000

SYSTEM_HOMES = {
    "/",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/nonexistent",
    "/run",
    "/var/empty",
}

def read_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def user_groups(username):
    groups = []
    try:
        pw = pwd.getpwnam(username)
        primary = grp.getgrgid(pw.pw_gid).gr_name
        groups.append(primary)
    except Exception:
        pass

    for g in grp.getgrall():
        if username in g.gr_mem and g.gr_name not in groups:
            groups.append(g.gr_name)

    return sorted(groups)

def has_authorized_keys(home):
    count = 0
    present = False

    if not home or not os.path.isdir(home):
        return False, 0

    for name in ["authorized_keys", "authorized_keys2"]:
        path = os.path.join(home, ".ssh", name)
        if os.path.isfile(path):
            present = True
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    count += len([
                        x for x in f.readlines()
                        if x.strip() and not x.strip().startswith("#")
                    ])
            except Exception:
                pass

    return present, count

def sudoers_text():
    text = read_file("/etc/sudoers")
    sudoers_d = "/etc/sudoers.d"

    if os.path.isdir(sudoers_d):
        for name in sorted(os.listdir(sudoers_d)):
            path = os.path.join(sudoers_d, name)
            if os.path.isfile(path):
                text += "\n" + read_file(path)

    return text

def sshd_text():
    text = read_file("/etc/ssh/sshd_config")
    sshd_d = "/etc/ssh/sshd_config.d"

    if os.path.isdir(sshd_d):
        for name in sorted(os.listdir(sshd_d)):
            if name.endswith(".conf"):
                text += "\n" + read_file(os.path.join(sshd_d, name))

    return text

def sudo_direct_user(username, text):
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith(username + " ") or s.startswith(username + "\t"):
            return True
    return False

def sudo_direct_group(groups, text):
    group_tokens = {"%" + g for g in groups}

    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue

        parts = s.split()
        if parts and parts[0] in group_tokens:
            return True

    return False

def detect_sftp_only(username, groups, shell, sshd):
    lower = sshd.lower()

    if "forcecommand internal-sftp" not in lower and "forcecommandinternal-sftp" not in lower.replace(" ", ""):
        return False

    lines = sshd.splitlines()
    in_match = False
    applies = False
    block = []

    for raw in lines + ["Match End"]:
        line = raw.strip()
        low = line.lower()

        if low.startswith("match "):
            if in_match and applies:
                joined = "\n".join(block).lower()
                if "forcecommand internal-sftp" in joined or "forcecommandinternal-sftp" in joined.replace(" ", ""):
                    return True

            in_match = True
            applies = False
            block = []

            parts = line.split()
            if len(parts) >= 3:
                criteria = parts[1].lower()
                values = " ".join(parts[2:]).replace(",", " ").split()

                if criteria == "user" and username in values:
                    applies = True

                if criteria == "group" and any(g in values for g in groups):
                    applies = True

            continue

        if in_match:
            block.append(line)

    shell_lower = (shell or "").lower()
    if shell_lower.endswith("/nologin") or shell_lower.endswith("/false"):
        if username.lower() in lower or any(g.lower() in lower for g in groups):
            return True

    return False

def has_real_home(home):
    if not home:
        return False

    if home in SYSTEM_HOMES:
        return False

    if home.startswith("/home/"):
        return True

    if home == "/root":
        return True

    return False

def account_type(username, uid, home, shell, ssh_user, sftp_only, sudo_access, docker_access):
    if username == "root":
        return "user"

    if has_real_home(home) and uid >= NORMAL_UID_MIN:
        return "user"

    if has_real_home(home) and (ssh_user or sftp_only or sudo_access or docker_access):
        return "user"

    return "service"

def main():
    sudo_text = sudoers_text()
    sshd = sshd_text()

    users = []
    service_accounts = []

    for p in pwd.getpwall():
        username = p.pw_name
        groups = user_groups(username)
        auth_present, auth_count = has_authorized_keys(p.pw_dir)

        shell = p.pw_shell or ""
        shell_allows_login = not (
            shell.endswith("/nologin") or
            shell.endswith("/false") or
            shell == ""
        )

        sudo_access = (
            username == "root" or
            "sudo" in groups or
            "admin" in groups or
            "wheel" in groups or
            sudo_direct_user(username, sudo_text) or
            sudo_direct_group(groups, sudo_text)
        )

        docker_access = "docker" in groups
        sftp_only = detect_sftp_only(username, groups, shell, sshd)

        ssh_user = bool(
            shell_allows_login
            and not sftp_only
            and (
                p.pw_uid >= NORMAL_UID_MIN
                or username == "root"
                or auth_present
                or sudo_access
                or docker_access
            )
        )

        access = []

        if ssh_user:
            access.append("SSH")
        if sftp_only:
            access.append("SFTP")
        if sudo_access:
            access.append("Sudo")
        if docker_access:
            access.append("Docker")
        if not access:
            access.append("None")

        acct_type = account_type(
            username=username,
            uid=p.pw_uid,
            home=p.pw_dir,
            shell=shell,
            ssh_user=ssh_user,
            sftp_only=sftp_only,
            sudo_access=sudo_access,
            docker_access=docker_access,
        )

        row = {
            "username": username,
            "uid": p.pw_uid,
            "gid": p.pw_gid,
            "home": p.pw_dir,
            "shell": shell,
            "primary_group": groups[0] if groups else None,
            "groups": groups,
            "authorized_keys_present": auth_present,
            "authorized_keys_count": auth_count,
            "ssh_user": ssh_user,
            "sftp_only": sftp_only,
            "sudo_access": sudo_access,
            "docker_access": docker_access,
            "account_type": acct_type,
            "access": access,
        }

        if acct_type == "user":
            users.append(row)
        else:
            service_accounts.append(row)

    print(json.dumps({
        "collector": "iam_users",
        "asset_id": os.environ.get("ASSET_ID", socket.gethostname()),
        "hostname": socket.gethostname(),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "users": users,
        "service_accounts": service_accounts,
    }, indent=2))

if __name__ == "__main__":
    main()
