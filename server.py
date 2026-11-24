#!/usr/bin/python3
"""vps-mcp — read-only MCP server for example-vps.

Runs as the unprivileged `agent` user, launched over stdio by OpenCode.
Privileged reads are delegated to /usr/local/sbin/vps-mcp-helper, which systemd
starts as a per-connection root service when a request arrives on the Unix
socket /run/vps-mcp/helper.sock. The request travels as JSON; the helper accepts
no arguments.

Design constraints:
  * Python standard library only (no venv, no third-party packages)
  * no network listener of its own
  * no sudo, no setuid, no privilege escalation from this process
  * read-only: no mutating commands are implemented anywhere in this project
  * stdout carries only newline-delimited JSON-RPC; diagnostics go to stderr
"""

import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

SERVER_NAME = "vps"
SERVER_VERSION = "1.2.0"
DOCS_ROOT = os.environ.get("VPS_MCP_DOCS_ROOT", "/home/ops/vps-docs")
HELPER_SOCKET = os.environ.get("VPS_MCP_HELPER_SOCKET", "/run/vps-mcp/helper.sock")
SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
MAX_TEXT = 120_000
MAX_HELPER_RESPONSE = 400_000
HTTP_TIMEOUT = 10

INSTRUCTIONS = (
    "The vps_* tools are read-only diagnostics for this VPS. They run through a "
    "narrow root helper (no arguments, fixed subcommands) and never change state. "
    "Use them instead of guessing about containers, listeners, backups, "
    "certificates, firewall, or systemd units; vps_journal searches the journal, "
    "vps_disk_usage reports filesystem consumption, vps_restic_snapshots lists "
    "backup snapshots, and vps_nginx_site shows one site's Nginx config. Never "
    "ask for mutating sudo: none exists. Results are truncated and secrets are "
    "redacted best-effort; do not paste credentials into chat even if one slips "
    "through."
)

# name, public hostname, loopback port (None = no loopback probe)
APPS = (
    ("portainer", "portainer.example.com", 9000),
    ("dozzle", "logs.example.com", 8080),
    ("uptime-kuma", "status.example.com", 3001),
    ("navidrome", "music.example.com", 4533),
    ("musicgrabber", "musicgrabber.example.com", 38274),
    ("opengym", "gym.example.com", 8090),
    ("n8n", "n8n.example.com", 5679),
    ("root-domain", "example.com", None),
)


class ToolFailure(Exception):
    """A tool-level failure that should be reported as isError, not a crash."""


def log(message):
    sys.stderr.write("[vps-mcp] %s\n" % message)
    sys.stderr.flush()


def send(payload):
    sys.stdout.write(json.dumps(payload, separators=(",", ":"), default=str) + "\n")
    sys.stdout.flush()


def truncate(text, limit=MAX_TEXT):
    if len(text) <= limit:
        return text
    return text[:limit] + "\n\n... output truncated by vps-mcp (%d chars total) ..." % len(text)


# ---------------------------------------------------------------- helper calls


def call_helper(payload, timeout=90):
    """Send one JSON request to the root helper over the systemd-activated
    Unix socket. The helper runs as a per-connection service with
    NoNewPrivileges=true; there is no sudo and no setuid involved."""
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > 65_536:
        raise ToolFailure("helper request too large")

    chunks = []
    total = 0
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(HELPER_SOCKET)
            conn.sendall(encoded)
            conn.shutdown(socket.SHUT_WR)
            while True:
                chunk = conn.recv(65_536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_HELPER_RESPONSE:
                    raise ToolFailure("helper response too large")
                chunks.append(chunk)
    except FileNotFoundError:
        raise ToolFailure(
            "helper socket %s is missing; is vps-mcp-helper.socket enabled?" % HELPER_SOCKET
        )
    except ConnectionRefusedError:
        raise ToolFailure(
            "helper socket refused the connection; check vps-mcp-helper.socket"
        )
    except PermissionError:
        raise ToolFailure(
            "permission denied on helper socket; check root:agent ownership and mode 0660"
        )
    except TimeoutError:
        raise ToolFailure("helper timed out after %ds" % timeout)
    except OSError as exc:
        raise ToolFailure("helper transport error: %s" % exc)

    raw = b"".join(chunks)
    if not raw.strip():
        raise ToolFailure("helper returned an empty response")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise ToolFailure("helper returned non-JSON output")

    if isinstance(data, dict) and data.get("error"):
        raise ToolFailure(str(data["error"]))
    return data


# ------------------------------------------------------------- local app probes


def tls_expiry_days(host, timeout=HTTP_TIMEOUT):
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert()
    not_after = cert.get("notAfter")
    if not not_after:
        return None
    return round((ssl.cert_time_to_seconds(not_after) - time.time()) / 86400, 1)


def probe_app(app):
    name, host, port = app
    result = {"app": name, "host": host, "loopback_port": port}

    if port is not None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3):
                result["loopback_tcp"] = "open"
        except OSError as exc:
            result["loopback_tcp"] = "closed (%s)" % exc.__class__.__name__

    request = urllib.request.Request(
        "https://%s/" % host,
        headers={"User-Agent": "vps-mcp/1.0"},
        method="GET",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            response.read(2048)
            result["https_status"] = response.status
    except urllib.error.HTTPError as exc:
        result["https_status"] = exc.code
        exc.close()
    except urllib.error.URLError as exc:
        result["https_status"] = None
        result["https_error"] = str(exc.reason)[:300]
    except (OSError, ssl.SSLError) as exc:
        result["https_status"] = None
        result["https_error"] = "%s: %s" % (exc.__class__.__name__, exc)
    result["https_ms"] = round((time.monotonic() - started) * 1000)

    try:
        result["tls_days_left"] = tls_expiry_days(host)
    except (OSError, ssl.SSLError) as exc:
        result["tls_days_left"] = None
        result["tls_error"] = "%s: %s" % (exc.__class__.__name__, exc)

    # Any HTTP status means the public path answered; 5xx/None is unhealthy.
    status = result.get("https_status")
    result["reachable"] = bool(status) and status < 500
    return result


def tool_app_status(_args):
    with ThreadPoolExecutor(max_workers=8) as pool:
        apps = list(pool.map(probe_app, APPS))
    failing = [a["app"] for a in apps if not a["reachable"]]
    soon = [
        {"app": a["app"], "days_left": a["tls_days_left"]}
        for a in apps
        if a.get("tls_days_left") is not None and a["tls_days_left"] < 21
    ]
    return {
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "failing": failing,
        "tls_expiring_soon": soon,
        "apps": apps,
    }


# ------------------------------------------------------------- docs resources


def docs_index():
    files = []
    for relative in ("AGENTS.md", "README.md"):
        if os.path.isfile(os.path.join(DOCS_ROOT, relative)):
            files.append(relative)
    docs_dir = os.path.join(DOCS_ROOT, "docs")
    if os.path.isdir(docs_dir):
        for name in sorted(os.listdir(docs_dir)):
            if name.endswith(".md") and os.path.isfile(os.path.join(docs_dir, name)):
                files.append("docs/" + name)
    return files


def safe_docs_path(relative):
    relative = (relative or "").strip().lstrip("/")
    if not relative or relative.endswith("/"):
        raise ToolFailure("invalid docs path")
    if not relative.endswith(".md"):
        raise ToolFailure("only Markdown files are readable")
    root = os.path.realpath(DOCS_ROOT)
    full = os.path.realpath(os.path.join(root, relative))
    if full != root and not full.startswith(root + os.sep):
        raise ToolFailure("path escapes the docs directory")
    if not os.path.isfile(full):
        raise ToolFailure("not found: %s" % relative)
    return full


def read_docs(relative):
    with open(safe_docs_path(relative), "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def tool_docs_read(args):
    relative = args.get("path", "")
    text = read_docs(relative)
    return {
        "path": relative,
        "bytes": len(text.encode("utf-8")),
        "content": truncate(text),
    }


# ----------------------------------------------------------------- tool schemas


TOOLS = [
    {
        "name": "vps_overview",
        "description": "Host vitals: uptime, load, RAM/swap, disk and inode usage, "
        "Docker space usage, OS/kernel, systemd state and failed units. Read-only.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "vps_containers",
        "description": "Every Docker container with Compose project/service, image, "
        "state, health, restart count, networks and published ports. Read-only.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "vps_container_logs",
        "description": "Bounded recent logs for ONE container (1-200 lines, default "
        "50). ANSI stripped and secrets redacted best-effort.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "container": {
                    "type": "string",
                    "description": "Exact container name from vps_containers, e.g. n8n",
                },
                "lines": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 50,
                },
            },
            "required": ["container"],
            "additionalProperties": False,
        },
    },
    {
        "name": "vps_listeners",
        "description": "TCP listeners with owning process and scope; flags any "
        "public listener outside 22/80/443.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "vps_backup_status",
        "description": "restic backup timer, last service result, journal tail, "
        "last snapshot line and credential-file modes (never contents).",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "vps_certs_nginx",
        "description": "Let's Encrypt certificate inventory and expiry, nginx "
        "syntax test, and server_name/listen map per config file.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "vps_security_status",
        "description": "UFW, Fail2ban, sshd policy, secret-file permission metadata, "
        "opencode-agent state and authorized-key fingerprints (never key material).",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "vps_unit_status",
        "description": "systemctl status/show for one systemd unit (service, timer, "
        "socket, target, mount or path).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "unit": {
                    "type": "string",
                    "description": "Exact unit name, e.g. opencode-agent.service",
                }
            },
            "required": ["unit"],
            "additionalProperties": False,
        },
    },
    {
        "name": "vps_journal",
        "description": "Recent journald entries, optionally filtered to one unit and/or "
        "a PCRE pattern (1-500 lines, default 100). Redacted best-effort.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "unit": {
                    "type": "string",
                    "description": "Optional exact unit name, e.g. nginx.service",
                },
                "pattern": {
                    "type": "string",
                    "description": "Optional grep (PCRE) filter; plain text is fine",
                },
                "lines": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 100,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "vps_disk_usage",
        "description": "All filesystems from df plus bounded du totals for /srv/apps, "
        "/srv/stacks, /srv/media and /var/lib/docker. Read-only.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "vps_restic_snapshots",
        "description": "List the 10 latest restic snapshots (id, time, tags, summary). "
        "Uses the root-only restic credentials without exposing them. Read-only.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "vps_nginx_site",
        "description": "Show one Nginx site config file (basename reported by nginx -T), "
        "redacted; an unknown name returns the list of available config files. Read-only.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "site": {
                    "type": "string",
                    "description": "Config filename, e.g. gym.example.com.conf",
                }
            },
            "required": ["site"],
            "additionalProperties": False,
        },
    },
    {
        "name": "vps_app_status",
        "description": "Loopback TCP check, public HTTPS status and TLS days-left "
        "for each deployed app hostname.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "vps_docs_read",
        "description": "Read one Markdown file from /home/ops/vps-docs "
        "(AGENTS.md, README.md, docs/*.md).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path, e.g. docs/08-known-issues.md",
                }
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
]


HANDLERS = {
    "vps_overview": lambda _args: call_helper({"command": "overview"}),
    "vps_containers": lambda _args: call_helper({"command": "containers"}),
    "vps_container_logs": lambda args: call_helper(
        {
            "command": "container_logs",
            "container": args.get("container", ""),
            "lines": args.get("lines", 50),
        }
    ),
    "vps_listeners": lambda _args: call_helper({"command": "listeners"}),
    "vps_backup_status": lambda _args: call_helper({"command": "backup_status"}),
    "vps_certs_nginx": lambda _args: call_helper({"command": "certs_nginx"}),
    "vps_security_status": lambda _args: call_helper({"command": "security_status"}),
    "vps_unit_status": lambda args: call_helper(
        {"command": "unit_status", "unit": args.get("unit", "")}
    ),
    "vps_journal": lambda args: call_helper(
        {
            "command": "journal",
            "unit": args.get("unit", ""),
            "pattern": args.get("pattern", ""),
            "lines": args.get("lines", 100),
        }
    ),
    "vps_disk_usage": lambda _args: call_helper({"command": "disk_usage"}),
    "vps_restic_snapshots": lambda _args: call_helper({"command": "restic_snapshots"}),
    "vps_nginx_site": lambda args: call_helper(
        {"command": "nginx_site", "site": args.get("site", "")}
    ),
    "vps_app_status": tool_app_status,
    "vps_docs_read": tool_docs_read,
}


# --------------------------------------------------------------------- prompts


PROMPTS = {
    "health": {
        "description": "Run a full read-only VPS health sweep and summarise anomalies",
        "arguments": [],
        "text": (
            "Run a read-only health check of this VPS. Call vps_overview, "
            "vps_containers, vps_listeners, vps_backup_status, vps_certs_nginx and "
            "vps_app_status. Then summarise, in this order: (1) anything failing or "
            "unhealthy, (2) disk/RAM/swap headroom, (3) containers not running or "
            "unhealthy, (4) listeners that are public but not 22/80/443, (5) backup "
            "age and result, (6) certificate expiry under 21 days, (7) apps whose "
            "public HTTPS or loopback check failed. State the exact tool values you "
            "relied on. Do not propose or run any mutating command."
        ),
    },
    "incident": {
        "description": "Collect evidence for a VPS incident without changing anything",
        "arguments": [
            {
                "name": "symptom",
                "description": "What the user observed, e.g. 'n8n returns 502'",
                "required": True,
            }
        ],
        "text": (
            "An incident was reported: {symptom}. Collect evidence before drawing "
            "conclusions: vps_overview, vps_containers, vps_listeners, "
            "vps_app_status, and vps_certs_nginx. Then use vps_unit_status for the "
            "affected systemd unit and vps_container_logs (max 100 lines) for the "
            "affected container. Report exactly which tools you called and their "
            "output, separate facts from hypotheses, and do not restart or change "
            "anything."
        ),
    },
}


def prompt_text(name, arguments):
    spec = PROMPTS[name]
    text = spec["text"]
    for argument in spec["arguments"]:
        key = argument["name"]
        value = (arguments or {}).get(key, "")
        if argument.get("required") and not value:
            raise ToolFailure("missing required prompt argument: %s" % key)
        text = text.replace("{%s}" % key, value)
    return text


# ---------------------------------------------------------------- JSON-RPC loop


class ProtocolError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def handle_request(message):
    method = message.get("method")
    params = message.get("params") or {}

    if method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOLS else "2025-06-18"
        return {
            "protocolVersion": version,
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"subscribe": False, "listChanged": False},
                "prompts": {"listChanged": False},
            },
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": INSTRUCTIONS,
        }

    if method == "ping":
        return {}

    if method == "tools/list":
        return {"tools": TOOLS}

    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        handler = HANDLERS.get(name)
        if handler is None:
            raise ProtocolError(-32602, "unknown tool: %s" % name)
        try:
            result = handler(arguments)
            return {
                "content": [{"type": "text", "text": truncate(json.dumps(result, indent=2, default=str))}],
                "isError": False,
            }
        except ToolFailure as exc:
            return {"content": [{"type": "text", "text": "ERROR: %s" % exc}], "isError": True}
        except Exception as exc:  # noqa: BLE001 - report, never crash the server
            log("tool %s crashed: %r" % (name, exc))
            return {
                "content": [{"type": "text", "text": "ERROR: %s: %s" % (type(exc).__name__, exc)}],
                "isError": True,
            }

    if method == "resources/list":
        return {
            "resources": [
                {
                    "uri": "vps-docs://" + relative,
                    "name": relative,
                    "description": "VPS operations documentation (synced from the owner's Mac)",
                    "mimeType": "text/markdown",
                }
                for relative in docs_index()
            ]
        }

    if method == "resources/templates/list":
        return {"resourceTemplates": []}

    if method == "resources/read":
        uri = params.get("uri", "")
        prefix = "vps-docs://"
        if not uri.startswith(prefix):
            raise ProtocolError(-32602, "unsupported resource URI: %s" % uri)
        relative = uri[len(prefix):]
        try:
            text = read_docs(relative)
        except ToolFailure as exc:
            raise ProtocolError(-32602, str(exc))
        return {
            "contents": [
                {"uri": uri, "mimeType": "text/markdown", "text": truncate(text)}
            ]
        }

    if method == "prompts/list":
        return {
            "prompts": [
                {
                    "name": name,
                    "description": spec["description"],
                    "arguments": spec["arguments"],
                }
                for name, spec in PROMPTS.items()
            ]
        }

    if method == "prompts/get":
        name = params.get("name")
        if name not in PROMPTS:
            raise ProtocolError(-32602, "unknown prompt: %s" % name)
        try:
            text = prompt_text(name, params.get("arguments"))
        except ToolFailure as exc:
            raise ProtocolError(-32602, str(exc))
        return {
            "description": PROMPTS[name]["description"],
            "messages": [{"role": "user", "content": {"type": "text", "text": text}}],
        }

    if method == "logging/setLevel":
        return {}

    raise ProtocolError(-32601, "method not found: %s" % method)


def main():
    log("vps-mcp %s starting (docs=%s helper=%s)" % (SERVER_VERSION, DOCS_ROOT, HELPER_SOCKET))
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            log("ignoring malformed JSON line")
            continue
        if isinstance(message, list):
            log("ignoring batch request")
            continue
        if not isinstance(message, dict):
            continue

        is_notification = "id" not in message
        try:
            result = handle_request(message)
        except ProtocolError as exc:
            if not is_notification:
                send(
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {"code": exc.code, "message": exc.message},
                    }
                )
            continue
        except Exception as exc:  # noqa: BLE001
            log("request failed: %r" % exc)
            if not is_notification:
                send(
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {"code": -32603, "message": "internal error: %s" % exc},
                    }
                )
            continue

        if is_notification:
            continue
        send({"jsonrpc": "2.0", "id": message.get("id"), "result": result})


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        pass
