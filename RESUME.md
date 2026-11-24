# Resume notes — vps-mcp

Suggested bullets (trim to fit):

- Built a **production MCP (Model Context Protocol) server** (Python,
  stdlib-only) exposing 14 read-only diagnostic tools, resources, and prompts
  for a self-hosted Linux VPS; implemented JSON-RPC 2.0 over stdio with
  protocol version negotiation across four MCP revisions.
- Designed a **privilege-separation architecture** using systemd socket
  activation: a root helper behind a 0660 Unix socket with a fixed command
  allowlist, strict input validation, stat-only secret checks, and output
  redaction — no sudo, no setuid, no Docker-group membership, compatible with
  `NoNewPrivileges=true` sandboxing.
- Harden and operate on a real host: systemd units (socket + templated
  oneshot), Docker, journald, Nginx/TLS, UFW/Fail2ban, restic backups, on an
  Oracle Cloud ARM64 Ubuntu VPS; implemented end-to-end verification with
  positive and negative security tests.
- Wrote a **pytest suite** (redaction, validation, full stdio integration
  against a fake helper socket) and a GitHub Actions CI pipeline; documented
  security model, architecture, and operations runbooks.
- Made agent tooling **LLM-usable**: bounded outputs, clear schemas, redaction
  and deny-by-default policies, plus "health" and "incident" prompt playbooks.

Skills demonstrated: MCP protocol design, AI agent/tool engineering, secure
systems programming (Python), Linux/DevOps (systemd, Docker, journald, TLS,
firewalls, backups), testing & CI, technical writing, operational discipline
(phased rollout, verification gates, rollback).
