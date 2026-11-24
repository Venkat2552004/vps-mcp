import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


class FakeHelper:
    def __init__(self, path, response):
        self.response = response
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(str(path))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.recv(65536)
                    conn.sendall(json.dumps(self.response).encode())
                except OSError:
                    pass

    def close(self):
        self.sock.close()


class ServerProcess:
    def __init__(self, env):
        self.proc = subprocess.Popen(
            [sys.executable, str(ROOT / "server.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        self.next_id = 1

    def request(self, method, params=None):
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            message["params"] = params
        self.next_id += 1
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        assert line, "server produced no response"
        return json.loads(line)

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


@pytest.fixture()
def stack(tmp_path):
    # AF_UNIX paths are limited to ~104 chars on macOS; keep the socket short.
    sock_dir = tempfile.mkdtemp()
    sock_path = Path(sock_dir) / "h.sock"
    docs = tmp_path / "docs-root"
    (docs / "docs").mkdir(parents=True)
    (docs / "AGENTS.md").write_text("# Ops docs\n")
    (docs / "docs" / "00-test.md").write_text("# Test doc\n")

    fake = FakeHelper(sock_path, {"ok": True, "note": "fake helper"})
    env = os.environ.copy()
    env["VPS_MCP_HELPER_SOCKET"] = str(sock_path)
    env["VPS_MCP_DOCS_ROOT"] = str(docs)

    server = ServerProcess(env)
    try:
        yield server
    finally:
        server.close()
        fake.close()
        shutil.rmtree(sock_dir, ignore_errors=True)


def test_initialize(stack):
    result = stack.request(
        "initialize", {"protocolVersion": "2025-06-18"}
    )["result"]
    assert result["serverInfo"]["name"] == "vps"
    assert "tools" in result["capabilities"]


def test_tools_list_exposes_catalog(stack):
    tools = stack.request("tools/list")["result"]["tools"]
    names = {tool["name"] for tool in tools}
    assert len(tools) == 14
    assert {"vps_overview", "vps_journal", "vps_disk_usage", "vps_nginx_site"} <= names


def test_tool_call_round_trips_through_helper(stack):
    response = stack.request(
        "tools/call", {"name": "vps_overview", "arguments": {}}
    )["result"]
    assert response["isError"] is False
    assert "fake helper" in response["content"][0]["text"]


def test_unknown_tool_is_an_error(stack):
    response = stack.request(
        "tools/call", {"name": "vps_restart_everything", "arguments": {}}
    )
    assert response["error"]["code"] == -32602


def test_resources_list_docs_tree(stack):
    resources = stack.request("resources/list")["result"]["resources"]
    uris = {resource["uri"] for resource in resources}
    assert "vps-docs://AGENTS.md" in uris
    assert "vps-docs://docs/00-test.md" in uris


def test_resources_read(stack):
    contents = stack.request(
        "resources/read", {"uri": "vps-docs://AGENTS.md"}
    )["result"]["contents"]
    assert contents[0]["text"] == "# Ops docs\n"


def test_resources_read_rejects_traversal(stack):
    response = stack.request("resources/read", {"uri": "vps-docs://../outside.md"})
    assert response["error"]["code"] == -32602


def test_resources_read_rejects_non_markdown(stack):
    response = stack.request("resources/read", {"uri": "vps-docs://AGENTS.txt"})
    assert response["error"]["code"] == -32602


def test_prompts_available(stack):
    prompts = stack.request("prompts/list")["result"]["prompts"]
    assert {prompt["name"] for prompt in prompts} == {"health", "incident"}
