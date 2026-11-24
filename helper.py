#!/usr/bin/python3
"""vps-mcp-helper — read-only root helper for the VPS MCP server.

Invocation contract (enforced by /etc/systemd/system/vps-mcp-helper.socket and
the per-connection vps-mcp-helper@.service):
    request  : one JSON object on stdin (sent over /run/vps-mcp/helper.sock)
    response : one JSON object on stdout
    errors   : {"error": "..."} (still a JSON object)
    diagnostics: stderr only

Security contract:
  * accepts no argv; reads a single JSON request from stdin
  * fixed command allowlist, no shell, no eval, no command substitution
  * container names must exist in `docker ps -a`; unit names match a strict
    regex and are passed after `--`
  * secret files are only stat()ed, never read
  * output is bounded; log text is redacted best-effort before returning
  * every implemented command is read-only
"""

import datetime
import grp
import json
import os
import pwd
import re
import subprocess
import sys
import time

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SAFE_ENV = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C", "HOME": "/root"}
MAX_OUTPUT = 180_000
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

SECRET_FILES = (
    "/srv/stacks/data/.env",
    "/srv/stacks/monitoring/.env",
    "/etc/restic/azure.env",
    "/etc/restic/repository-password",
    "/etc/restic/rclone.conf",
    "/etc/nginx/.monitoring-htpasswd",
    "/home/ops/opencode-agent.env",
)

UNIT_RE = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9@._:-]*\.(service|timer|socket|target|mount|path)$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

REDACTIONS = (
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)([?&]sig=)[^&\s]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
    (re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|authorization)\b\s*[=:]\s*(\"[^\"]*\"|'[^']*'|\S+)"), r"\1=[REDACTED]"),
)


class RequestError(Exception):
    pass


def run(argv, timeout=25, check=False, extra_env=None):
    env = dict(SAFE_ENV)
    if extra_env:
        env.update({key: str(value) for key, value in extra_env.items()})
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            env=env,
            shell=False,
        )
    except FileNotFoundError:
        return 127, "", "%s: command not found" % argv[0]
    except subprocess.TimeoutExpired:
        return 124, "", "%s: timed out after %ds" % (argv[0], timeout)
    if check and proc.returncode != 0:
        raise RequestError(
            "%s failed (exit %d): %s"
            % (" ".join(argv[:2]), proc.returncode, (proc.stderr or proc.stdout).strip()[:400])
        )
    return proc.returncode, proc.stdout, proc.stderr


def redact(text):
    text = ANSI.sub("", text)
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def iso(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).astimezone().isoformat(timespec="seconds")


def stat_meta(path):
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return {"path": path, "exists": False}
    except OSError as exc:
        return {"path": path, "exists": False, "error": exc.__class__.__name__}
    return {
        "path": path,
        "exists": True,
        "mode": format(info.st_mode & 0o777, "04o"),
        "owner": pwd.getpwuid(info.st_uid).pw_name,
        "group": grp.getgrgid(info.st_gid).gr_name,
        "size": info.st_size,
        "mtime": iso(info.st_mtime),
    }


def read_first(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


# ------------------------------------------------------------------- commands


def cmd_overview(_request):
    uptime_seconds = float(read_first("/proc/uptime").split()[0])
    load = read_first("/proc/loadavg").split()

    memory = {}
    for line in read_first("/proc/meminfo").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        memory[key.strip()] = int(value.split()[0]) if value.split() else 0

    def mib(key):
        return round(memory.get(key, 0) / 1024, 1)

    total = mib("MemTotal")
    available = mib("MemAvailable")
    swap_total = mib("SwapTotal")
    swap_free = mib("SwapFree")

    root_fs = run(["df", "-P", "-B1", "/"])[1].splitlines()
    disk = {}
    if len(root_fs) >= 2:
        fields = root_fs[-1].split()
        if len(fields) >= 6:
            disk = {
                "filesystem": fields[0],
                "size_gib": round(int(fields[1]) / 1024**3, 1),
                "used_gib": round(int(fields[2]) / 1024**3, 1),
                "available_gib": round(int(fields[3]) / 1024**3, 1),
                "used_pct": fields[4],
                "mount": fields[5],
            }

    inode_lines = run(["df", "-Pi", "/"])[1].splitlines()
    inodes = {}
    if len(inode_lines) >= 2:
        fields = inode_lines[-1].split()
        if len(fields) >= 6:
            inodes = {
                "total": int(fields[1]),
                "used": int(fields[2]),
                "free": int(fields[3]),
                "used_pct": fields[4],
            }

    os_release = {}
    for line in read_first("/etc/os-release").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key in ("PRETTY_NAME", "VERSION_ID"):
                os_release[key] = value.strip().strip('"')

    docker_df = []
    rc, stdout, _ = run(["docker", "system", "df", "--format", "json"])
    if rc == 0:
        for line in stdout.splitlines():
            try:
                docker_df.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    failed_units = []
    rc, stdout, _ = run(["systemctl", "list-units", "--failed", "--no-legend", "--plain", "--no-pager"])
    if rc == 0:
        for line in stdout.splitlines():
            fields = line.split()
            if fields:
                failed_units.append(fields[0])

    return {
        "uptime_seconds": int(uptime_seconds),
        "uptime_human": "%dd %dh %dm"
        % (uptime_seconds // 86400, (uptime_seconds % 86400) // 3600, (uptime_seconds % 3600) // 60),
        "load": {
            "1m": float(load[0]) if load else None,
            "5m": float(load[1]) if len(load) > 1 else None,
            "15m": float(load[2]) if len(load) > 2 else None,
            "runnable": load[3] if len(load) > 3 else None,
        },
        "cpu_count": os.cpu_count(),
        "memory_mib": {
            "total": total,
            "available": available,
            "used": round(total - available, 1),
            "used_pct": round(100 * (total - available) / total, 1) if total else None,
            "swap_total": swap_total,
            "swap_used": round(swap_total - swap_free, 1),
        },
        "disk_root": disk,
        "inodes_root": inodes,
        "os": os_release,
        "kernel": os.uname().release,
        "hostname": os.uname().nodename,
        "system_state": run(["systemctl", "is-system-running"])[1].strip() or "unknown",
        "failed_units": failed_units,
        "docker_space": docker_df,
    }


def cmd_containers(_request):
    rc, stdout, stderr = run(["docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}"])
    if rc != 0:
        raise RequestError("docker ps failed: %s" % (stderr or stdout).strip()[:400])

    containers = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        labels = {}
        for pair in (item.get("Labels") or "").split(","):
            if "=" in pair:
                key, value = pair.split("=", 1)
                labels[key] = value
        containers.append(
            {
                "name": item.get("Names"),
                "image": item.get("Image"),
                "state": item.get("State"),
                "status": item.get("Status"),
                "health": item.get("HealthStatus") or "none",
                "project": labels.get("com.docker.compose.project"),
                "service": labels.get("com.docker.compose.service"),
                "ports": item.get("Ports"),
                "networks": item.get("Networks"),
                "running_for": item.get("RunningFor"),
            }
        )

    names = [item["name"] for item in containers if item.get("name")]
    if names:
        rc, stdout, _ = run(
            ["docker", "inspect", "--format", "{{.Name}}|{{.RestartCount}}"] + names,
            timeout=30,
        )
        if rc == 0:
            restarts = {}
            for line in stdout.splitlines():
                name, _, count = line.partition("|")
                try:
                    restarts[name.lstrip("/")] = int(count)
                except ValueError:
                    pass
            for item in containers:
                item["restarts"] = restarts.get(item["name"])

    attention = [
        item["name"]
        for item in containers
        if item.get("health") == "unhealthy"
        or item.get("state") not in (None, "running")
    ]
    return {
        "count": len(containers),
        "attention": attention,
        "containers": containers,
    }


def cmd_container_logs(request):
    name = str(request.get("container", "")).strip()
    if not CONTAINER_RE.match(name):
        raise RequestError("invalid container name")

    rc, stdout, stderr = run(["docker", "ps", "-a", "--format", "{{.Names}}"])
    if rc != 0:
        raise RequestError("cannot list containers: %s" % (stderr or stdout).strip()[:300])
    if name not in stdout.split():
        raise RequestError("unknown container: %s" % name)

    try:
        lines = int(request.get("lines", 50))
    except (TypeError, ValueError):
        raise RequestError("lines must be an integer")
    lines = max(1, min(lines, 200))

    rc, stdout, stderr = run(
        ["docker", "logs", "--tail", str(lines), "--timestamps", name], timeout=20
    )
    text = redact((stdout + stderr)[-120_000:])
    return {
        "container": name,
        "lines_requested": lines,
        "docker_exit_code": rc,
        "log": text,
        "note": "stdout+stderr combined; secrets redacted best-effort",
    }


def cmd_listeners(_request):
    rc, stdout, stderr = run(["ss", "-ltnpH"])
    if rc != 0:
        raise RequestError("ss failed: %s" % (stderr or stdout).strip()[:300])

    listeners = []
    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[3]
        if ":" not in local:
            continue
        address, port_text = local.rsplit(":", 1)
        address = address.strip("[]")
        try:
            port = int(port_text)
        except ValueError:
            continue
        process = " ".join(fields[5:]) if len(fields) > 5 else ""
        match = re.search(r'\("([^"]+)"', process)
        process_name = match.group(1) if match else (process or None)
        public = address in ("0.0.0.0", "::", "*")
        loopback = address.startswith("127.") or address in ("::1", "localhost")
        listeners.append(
            {
                "address": address,
                "port": port,
                "process": process_name,
                "scope": "public" if public else ("loopback" if loopback else "other"),
                "expected_public": port in (22, 80, 443),
            }
        )

    unexpected = [
        item for item in listeners if item["scope"] == "public" and not item["expected_public"]
    ]
    return {
        "count": len(listeners),
        "unexpected_public": unexpected,
        "listeners": sorted(listeners, key=lambda item: (item["port"], item["address"])),
    }


def cmd_backup_status(_request):
    timer_text = run(["systemctl", "list-timers", "vps-backup.timer", "--no-pager", "--no-legend"])[1]

    props = {}
    rc, stdout, _ = run(
        [
            "systemctl",
            "show",
            "vps-backup.service",
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "Result",
            "-p",
            "ExecMainStatus",
            "-p",
            "ExecMainExitTimestamp",
        ]
    )
    for line in stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            props[key] = value

    timer_props = {}
    rc, stdout, _ = run(
        [
            "systemctl",
            "show",
            "vps-backup.timer",
            "-p",
            "NextElapseUSecRealtime",
            "-p",
            "LastTriggerUSec",
        ]
    )
    for line in stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            timer_props[key] = value

    rc, stdout, stderr = run(
        ["journalctl", "-u", "vps-backup.service", "-n", "400", "--no-pager", "-o", "short-iso"],
        timeout=30,
    )
    journal_text = stdout + stderr

    rc_snap, snap_out, _ = run(
        [
            "journalctl",
            "-u",
            "vps-backup.service",
            "-g",
            "snapshot [0-9a-f]+ saved",
            "-n",
            "1",
            "--no-pager",
            "-o",
            "short-iso",
        ],
        timeout=30,
    )

    last_snapshot = None
    snapshot_age_hours = None
    for line in reversed(snap_out.splitlines()):
        if "snapshot" in line and "saved" in line:
            last_snapshot = redact(line.strip())
            match = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d{2}:?\d{2})", line)
            if match:
                try:
                    moment = datetime.datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S%z")
                    snapshot_age_hours = round((time.time() - moment.timestamp()) / 3600, 1)
                except ValueError:
                    pass
            break

    errors = [
        redact(line.strip())
        for line in journal_text.splitlines()
        if re.search(r"(?i)\b(fatal|error|failed)\b", line)
    ][-10:]

    return {
        "timer": redact(timer_text.strip()),
        "service": props,
        "timer_properties": timer_props,
        "last_snapshot_line": last_snapshot,
        "last_snapshot_age_hours": snapshot_age_hours,
        "recent_error_lines": errors,
        "credential_files": [stat_meta(path) for path in (
            "/etc/restic/azure.env",
            "/etc/restic/repository-password",
            "/etc/restic/rclone.conf",
        )],
        "backup_units": [stat_meta(path) for path in (
            "/usr/local/sbin/vps-backup.sh",
            "/etc/systemd/system/vps-backup.service",
            "/etc/systemd/system/vps-backup.timer",
        )],
        "journal_tail": redact(journal_text[-40_000:]),
    }


def cmd_certs_nginx(_request):
    rc, stdout, stderr = run(["certbot", "certificates"], timeout=40)
    certbot_text = stdout + stderr

    certificates = []
    current = None
    for line in certbot_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Certificate Name:"):
            current = {
                "name": stripped.split(":", 1)[1].strip(),
                "domains": [],
                "expiry": None,
                "validity": None,
                "days_left": None,
            }
            certificates.append(current)
        elif current is not None and stripped.startswith("Domains:"):
            current["domains"] = [
                item.strip() for item in stripped.split(":", 1)[1].split(",") if item.strip()
            ]
        elif current is not None and stripped.startswith("Expiry Date:"):
            value = stripped.split(":", 1)[1].strip()
            match = re.search(r"(.+?)\s*\((VALID|INVALID|EXPIRED):\s*([^)]+)\)", value)
            if match:
                current["expiry"] = match.group(1).strip()
                current["validity"] = match.group(2)
                current["days_left"] = match.group(3).strip()

    rc_test, test_out, test_err = run(["nginx", "-t"])
    nginx_active = run(["systemctl", "is-active", "nginx"])[1].strip()

    rc_dump, dump_out, dump_err = run(["nginx", "-T"], timeout=40)
    sites = {}
    current_file = None
    for line in (dump_out + dump_err).splitlines():
        if line.startswith("# configuration file "):
            current_file = line[len("# configuration file "):].rstrip(":")
            sites.setdefault(current_file, {"server_names": [], "listen": []})
            continue
        if current_file is None:
            continue
        match = re.match(r"\s*server_name\s+([^;]+);", line)
        if match:
            sites[current_file]["server_names"].extend(match.group(1).split())
        match = re.match(r"\s*listen\s+([^;]+);", line)
        if match:
            sites[current_file]["listen"].append(match.group(1).strip())

    return {
        "certbot_exit_code": rc,
        "certificates": certificates,
        "nginx_active": nginx_active,
        "nginx_test": {
            "ok": rc_test == 0,
            "output": redact((test_out + test_err).strip()[:2000]),
        },
        "nginx_dump_exit_code": rc_dump,
        "server_names": {
            path: value["server_names"] for path, value in sites.items() if value["server_names"]
        },
        "listen": {path: value["listen"] for path, value in sites.items() if value["listen"]},
    }


def cmd_security_status(_request):
    ufw_text = run(["ufw", "status", "verbose"])[1]
    rc_f2b, f2b_out, f2b_err = run(["fail2ban-client", "status", "sshd"])

    wanted = {
        "passwordauthentication",
        "permitrootlogin",
        "pubkeyauthentication",
        "kbdinteractiveauthentication",
        "permitemptypasswords",
        "allowtcpforwarding",
        "x11forwarding",
        "maxauthtries",
    }
    ssh_policy = {}
    rc_sshd, sshd_out, _ = run(["sshd", "-T"])
    for line in sshd_out.splitlines():
        key, _, value = line.partition(" ")
        if key in wanted:
            ssh_policy[key] = value.strip()

    authorized_keys = "/home/ops/.ssh/authorized_keys"
    key_entries = []
    if os.path.isfile(authorized_keys):
        with open(authorized_keys, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                options = (
                    parts[0]
                    if parts and not parts[0].startswith(("ssh-", "ecdsa-", "sk-"))
                    else ""
                )
                key_type = next(
                    (token for token in parts if token.startswith(("ssh-", "ecdsa-", "sk-"))),
                    "unknown",
                )
                comment = parts[-1] if len(parts) > 2 else ""
                key_entries.append(
                    {"options": options, "key_type": key_type, "comment": comment}
                )

    rc_fp, fp_out, _ = run(["ssh-keygen", "-lf", authorized_keys])
    fingerprints = [line.strip() for line in fp_out.splitlines() if line.strip()]

    opencode_active = run(["systemctl", "is-active", "opencode-agent.service"])[1].strip()
    agent_passwd = pwd.getpwnam("agent")
    agent_groups = [
        group.gr_name for group in grp.getgrall() if "agent" in group.gr_mem
    ]

    return {
        "ufw": redact(ufw_text.strip()),
        "fail2ban_sshd": {
            "ok": rc_f2b == 0,
            "output": redact((f2b_out + f2b_err).strip()[-4000:]),
        },
        "sshd_policy": ssh_policy,
        "sshd_effective_read_ok": rc_sshd == 0,
        "secret_file_metadata": [stat_meta(path) for path in SECRET_FILES],
        "agent_user": {
            "name": agent_passwd.pw_name,
            "uid": agent_passwd.pw_uid,
            "home": agent_passwd.pw_dir,
            "shell": agent_passwd.pw_shell,
            "supplementary_groups": agent_groups,
            "docker_group": "docker" in agent_groups,
        },
        "authorized_keys": {
            "path": authorized_keys,
            "entries": key_entries,
            "fingerprints": fingerprints,
        },
        "opencode_agent": {
            "active": opencode_active,
            "listeners": [
                item
                for item in cmd_listeners(None)["listeners"]
                if item["port"] == 49374
            ],
        },
    }


def cmd_unit_status(request):
    unit = str(request.get("unit", "")).strip()
    if not UNIT_RE.match(unit):
        raise RequestError("invalid systemd unit name")

    rc, stdout, stderr = run(
        ["systemctl", "status", "--no-pager", "--lines=25", "--full", "--", unit], timeout=20
    )
    props = {}
    rc_show, show_out, _ = run(
        [
            "systemctl",
            "show",
            unit,
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "Result",
            "-p",
            "ExecMainStatus",
            "-p",
            "NRestarts",
            "-p",
            "ActiveEnterTimestamp",
        ]
    )
    for line in show_out.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            props[key] = value

    return {
        "unit": unit,
        "status_exit_code": rc,
        "status_text": redact((stdout + stderr)[:40_000]),
        "properties": props,
    }


SITE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
PATTERN_RE = re.compile(r"^[A-Za-z0-9 _.:/@=,()\[\]^$*+?|{}-]{1,200}$")

RESTIC_ENV = {
    "RESTIC_REPOSITORY": "rclone:azureblob:vps-backups/example-vps",
    "RESTIC_PASSWORD_FILE": "/etc/restic/repository-password",
    "RCLONE_CONFIG": "/etc/restic/rclone.conf",
}


def cmd_journal(request):
    unit = str(request.get("unit", "")).strip()
    pattern = str(request.get("pattern", "")).strip()
    if unit and not UNIT_RE.match(unit):
        raise RequestError("invalid systemd unit name")
    if pattern and not PATTERN_RE.match(pattern):
        raise RequestError("invalid journal pattern (plain text or simple PCRE only)")
    try:
        lines = int(request.get("lines", 100))
    except (TypeError, ValueError):
        raise RequestError("lines must be an integer")
    lines = max(1, min(lines, 500))

    argv = ["journalctl", "-n", str(lines), "--no-pager", "-o", "short-iso"]
    if unit:
        argv += ["-u", unit]
    if pattern:
        argv += ["-g", pattern]

    rc, stdout, stderr = run(argv, timeout=40)
    return {
        "unit": unit or "(all units)",
        "pattern": pattern or None,
        "lines_requested": lines,
        "journal_exit_code": rc,
        "entries": redact((stdout + stderr)[-150_000:]),
        "note": "journal text redacted best-effort",
    }


def cmd_disk_usage(_request):
    rc, stdout, stderr = run(["df", "-hP"], timeout=20)
    filesystems = redact((stdout + stderr).strip())

    targets = ["/srv/apps", "/srv/stacks", "/srv/media", "/var/lib/docker"]
    try:
        targets += [
            "/srv/apps/" + name
            for name in sorted(os.listdir("/srv/apps"))
            if os.path.isdir(os.path.join("/srv/apps", name))
        ]
    except OSError:
        pass
    targets = targets[:24]

    rc_du, du_out, du_err = run(["du", "-sx", "-B1"] + targets, timeout=60)
    usage = []
    for line in du_out.splitlines():
        size_text, _, path = line.partition("\t")
        try:
            size = int(size_text)
        except ValueError:
            continue
        usage.append({"path": path, "gib": round(size / 1024**3, 2)})

    return {
        "df": filesystems,
        "du_exit_code": rc_du,
        "du_error": redact(du_err.strip()[:2000]) if rc_du != 0 else None,
        "directory_usage": sorted(usage, key=lambda item: -item["gib"]),
        "note": "du uses -x (single filesystem) and is bounded to known data roots",
    }


def load_env_file(path):
    data = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
                    data[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return data


def cmd_restic_snapshots(_request):
    azure = load_env_file("/etc/restic/azure.env")
    account = azure.get("AZURE_ACCOUNT_NAME")
    sas = azure.get("AZURE_ACCOUNT_SAS")
    if not account or not sas:
        raise RequestError(
            "restic credentials missing in /etc/restic/azure.env (values are never shown)"
        )

    env = dict(RESTIC_ENV)
    env["AZURE_ACCOUNT_NAME"] = account
    env["AZURE_ACCOUNT_SAS"] = sas

    rc, stdout, stderr = run(["restic", "snapshots", "--json"], timeout=60, extra_env=env)
    data = []
    if rc == 0:
        try:
            parsed = json.loads(stdout or "[]")
            if isinstance(parsed, list):
                data = parsed
        except json.JSONDecodeError:
            pass

    latest = []
    def snapshot_when(item):
        try:
            return datetime.datetime.fromisoformat(str(item.get("time", ""))).timestamp()
        except ValueError:
            return 0.0

    for item in sorted(
        (entry for entry in data if isinstance(entry, dict)), key=snapshot_when
    )[-10:]:
        latest.append(
            {
                "short_id": item.get("short_id") or str(item.get("id", ""))[:8],
                "time": item.get("time"),
                "hostname": item.get("hostname"),
                "tags": item.get("tags"),
                "paths": item.get("paths"),
                "summary": item.get("summary"),
            }
        )

    return {
        "restic_exit_code": rc,
        "snapshot_count": len(data),
        "latest": latest,
        "error": redact(stderr.strip()[:2000]) if rc != 0 else None,
        "note": "repository URL and SAS are never included in output",
    }


def cmd_nginx_site(request):
    site = str(request.get("site", "")).strip()
    if not SITE_RE.match(site):
        raise RequestError("invalid site name; use a config filename like gym.example.conf")

    rc, stdout, stderr = run(["nginx", "-T"], timeout=40)
    if rc != 0:
        raise RequestError("nginx -T failed: %s" % redact((stderr or stdout).strip()[:500]))

    blocks = {}
    current = None
    for line in (stdout + stderr).splitlines():
        if line.startswith("# configuration file "):
            current = os.path.basename(line[len("# configuration file "):].rstrip(":"))
            blocks[current] = []
            continue
        if current is not None:
            blocks[current].append(line)

    match = None
    for name in blocks:
        if name == site or name == site + ".conf":
            match = name
            break
    if match is None:
        return {
            "site": site,
            "found": False,
            "available": sorted(blocks.keys())[:50],
        }

    return {
        "site": match,
        "found": True,
        "config": redact("\n".join(blocks[match])[:120_000]),
    }


COMMANDS = {
    "overview": cmd_overview,
    "containers": cmd_containers,
    "container_logs": cmd_container_logs,
    "listeners": cmd_listeners,
    "backup_status": cmd_backup_status,
    "certs_nginx": cmd_certs_nginx,
    "security_status": cmd_security_status,
    "unit_status": cmd_unit_status,
    "journal": cmd_journal,
    "disk_usage": cmd_disk_usage,
    "restic_snapshots": cmd_restic_snapshots,
    "nginx_site": cmd_nginx_site,
}


def emit(payload):
    text = json.dumps(payload, indent=2, default=str)
    if len(text) > MAX_OUTPUT:
        text = text[:MAX_OUTPUT] + "\n... helper output truncated ..."
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def main():
    if len(sys.argv) != 1:
        emit({"error": "arguments are not allowed; send a JSON request on stdin"})
        return
    try:
        request = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError):
        emit({"error": "stdin must contain one JSON object"})
        return
    if not isinstance(request, dict):
        emit({"error": "request must be a JSON object"})
        return

    command = request.get("command")
    handler = COMMANDS.get(command)
    if handler is None:
        emit({"error": "unknown command: %r" % command})
        return

    try:
        emit(handler(request))
    except RequestError as exc:
        emit({"error": str(exc)})
    except Exception as exc:  # noqa: BLE001 - never leak a traceback on stdout
        sys.stderr.write("vps-mcp-helper: %r\n" % exc)
        emit({"error": "%s: %s" % (type(exc).__name__, exc)})


if __name__ == "__main__":
    main()
