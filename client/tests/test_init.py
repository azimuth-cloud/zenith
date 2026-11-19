"""Test associating the client's SSH key with a subdomain via the registrar."""

import pathlib
import subprocess
from typing import Any

import pytest
import requests
from click.testing import CliRunner
from zenith.client import init
from zenith.client.cli import main
from zenith.client.config import InitConfig

REGISTRAR = "https://registrar.example.invalid"
PUBLIC_KEY = "ssh-ed25519 AAAAfake zenith-key"


class FakeResponse:
    """Stand in for a registrar response."""

    def __init__(self, status_code: int, body: Any, reason: str = "") -> None:
        """Store the status and the body, which is returned as JSON if not a str."""
        self.status_code = status_code
        self.body = body
        self.reason = reason

    def json(self) -> Any:
        """Return the body, failing like requests if it is not JSON."""
        if isinstance(self.body, str):
            raise requests.exceptions.JSONDecodeError("Expecting value", self.body, 0)
        return self.body


class FakeRegistrar:
    """Record requests to the registrar and give a canned response."""

    def __init__(self) -> None:
        """Accept the key by default."""
        self.requests: list[dict[str, Any]] = []
        self.response = FakeResponse(200, {"fingerprints": ["abc123"]})

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        """Record the request and return the canned response."""
        self.requests.append({"url": url, **kwargs})
        return self.response


@pytest.fixture
def registrar(monkeypatch: pytest.MonkeyPatch) -> FakeRegistrar:
    """Replace HTTP requests to the registrar with a fake."""
    fake = FakeRegistrar()
    monkeypatch.setattr(requests, "post", fake.post)
    return fake


def make_init_config(path: pathlib.Path, **overrides: Any) -> InitConfig:
    """Return an init config using the given SSH identity path."""
    return InitConfig(
        ssh_identity_path=path, registrar_url=REGISTRAR, token="token", **overrides
    )


def test_existing_identity_uploaded(
    registrar: FakeRegistrar, ssh_key_file: pathlib.Path
) -> None:
    """Check that an existing public key is associated using the token."""
    public_key = ssh_key_file.with_name("id_zenith.pub").read_text().strip()
    init.run(make_init_config(ssh_key_file, verify_ssl=False))
    assert registrar.requests == [
        {
            "url": f"{REGISTRAR}/associate",
            "json": {"token": "token", "public_keys": [public_key]},
            "verify": False,
        }
    ]


@pytest.fixture
def ssh_keygen(monkeypatch: pytest.MonkeyPatch) -> list[list[Any]]:
    """Replace ssh-keygen with a fake that writes a key pair where it is told."""
    commands: list[list[Any]] = []

    def check_call(command: list[Any]) -> int:
        """Write a key pair to the -f path, named as ssh-keygen names them."""
        commands.append(command)
        path = pathlib.Path(command[command.index("-f") + 1])
        path.write_text("private key\n")
        path.with_name(path.name + ".pub").write_text(PUBLIC_KEY + "\n")
        return 0

    monkeypatch.setattr(subprocess, "check_call", check_call)
    return commands


def test_new_identity_generated(
    registrar: FakeRegistrar, ssh_keygen: list[list[Any]], tmp_path: pathlib.Path
) -> None:
    """Check that a key pair is generated and uploaded if none exists."""
    path = tmp_path / "id_zenith"
    init.run(make_init_config(path))
    assert len(ssh_keygen) == 1
    assert path.exists()
    assert registrar.requests[0]["json"]["public_keys"] == [PUBLIC_KEY]


@pytest.mark.xfail(
    strict=True,
    reason="ensure_ssh_identity reads path.with_suffix('.pub'), but ssh-keygen "
    "writes '<path>.pub', so identity paths containing a dot read the wrong file",
)
def test_new_identity_with_dotted_path(
    registrar: FakeRegistrar, ssh_keygen: list[list[Any]], tmp_path: pathlib.Path
) -> None:
    """Check that the public key is found for an identity path with an extension."""
    init.run(make_init_config(tmp_path / "zenith.key"))
    assert registrar.requests[0]["json"]["public_keys"] == [PUBLIC_KEY]


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (
            FakeResponse(409, {"detail": "Unable to associate public key."}),
            "Unable to associate public key",
        ),
        (
            FakeResponse(502, "<html>Bad Gateway</html>", "Bad Gateway"),
            "502 Bad Gateway",
        ),
    ],
    ids=["registrar-error", "non-json-error"],
)
def test_registrar_error(
    response: FakeResponse,
    message: str,
    registrar: FakeRegistrar,
    ssh_key_file: pathlib.Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Check that a rejected association logs the reason and exits non-zero."""
    registrar.response = response
    with pytest.raises(SystemExit) as exc:
        init.run(make_init_config(ssh_key_file))
    assert exc.value.code == 1
    assert caplog.messages[-1] == message


@pytest.mark.xfail(
    strict=True,
    reason="a connection error to the registrar escapes as a traceback instead of "
    "being logged with a non-zero exit, unlike an error response",
)
def test_registrar_unreachable(
    monkeypatch: pytest.MonkeyPatch,
    ssh_key_file: pathlib.Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Check that an unreachable registrar logs the error and exits non-zero."""

    def post(url: str, **kwargs: Any) -> None:
        """Fail to connect to the registrar."""
        raise requests.ConnectionError("Name or service not known")

    monkeypatch.setattr(requests, "post", post)
    with pytest.raises(SystemExit) as exc:
        init.run(make_init_config(ssh_key_file))
    assert exc.value.code == 1
    assert "Name or service not known" in caplog.text


@pytest.mark.usefixtures("restore_logging")
def test_cli_init(registrar: FakeRegistrar, ssh_key_file: pathlib.Path) -> None:
    """Check that the init command uses the registrar and token from the CLI."""
    result = CliRunner().invoke(
        main,
        [
            "init",
            f"--registrar-url={REGISTRAR}/",
            "--token=cli-token",
            f"--ssh-identity-path={ssh_key_file}",
        ],
    )
    assert result.exit_code == 0, result.output
    assert registrar.requests[0]["url"] == f"{REGISTRAR}/associate"
    assert registrar.requests[0]["json"]["token"] == "cli-token"
