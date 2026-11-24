import importlib.util
import io
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location("helper", ROOT / "helper.py")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def test_redacts_password_assignments():
    text = helper.redact("password=hunter2\nDB_PASSWORD: s3cret")
    assert "hunter2" not in text
    assert "s3cret" not in text
    assert "[REDACTED]" in text


def test_redacts_bearer_tokens():
    text = helper.redact("Authorization: Bearer abc.def.ghi")
    assert "abc.def.ghi" not in text


def test_redacts_sig_query_parameter():
    text = helper.redact("https://acct.example.net/x?sig=abc%2Fdef&se=1")
    assert "abc%2Fdef" not in text


def test_redacts_url_credentials():
    text = helper.redact("https://user:secret@example.com/path")
    assert "secret" not in text


def test_strips_ansi():
    assert helper.redact("\x1b[31merror\x1b[0m") == "error"


@pytest.mark.parametrize(
    "name",
    ["nginx.service", "vps-backup.timer", "agent@1.service", "a.socket", "x.mount"],
)
def test_unit_names_accepted(name):
    assert helper.UNIT_RE.match(name)


@pytest.mark.parametrize("name", ["-rf", "nginx", "a; rm -rf /", "unit.scope", ""])
def test_unit_names_rejected(name):
    assert not helper.UNIT_RE.match(name)


def test_container_names():
    assert helper.CONTAINER_RE.match("data-postgres-1")
    assert not helper.CONTAINER_RE.match("--privileged")
    assert not helper.CONTAINER_RE.match("a b")


def test_site_names():
    assert helper.SITE_RE.match("gym.example.com.conf")
    assert not helper.SITE_RE.match("../nginx.conf")
    assert not helper.SITE_RE.match("a;b")


def test_journal_pattern_charset():
    assert helper.PATTERN_RE.match("error|warn")
    assert not helper.PATTERN_RE.match("bad\nnewline")


def test_load_env_file(tmp_path):
    env = tmp_path / "azure.env"
    env.write_text('# comment\nAZURE_ACCOUNT_NAME="acct"\nnot a pair\n')
    data = helper.load_env_file(str(env))
    assert data == {"AZURE_ACCOUNT_NAME": "acct"}


def test_main_refuses_arguments(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["helper.py", "--help"])
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    helper.main()
    assert "arguments are not allowed" in capsys.readouterr().out
