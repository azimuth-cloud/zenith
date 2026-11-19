"""Test the tunnel negotiation with the Zenith SSHD server and the SSH process."""

import base64
import io
import json
import os
import pathlib
import stat
import subprocess
from collections.abc import Callable, Iterable, Iterator
from typing import Any

import pytest
from click.testing import CliRunner
from zenith.client import tunnel
from zenith.client.cli import main
from zenith.client.config import ConnectConfig


class FakeSSHProcess:
    """Stand in for the SSH subprocess, replaying output and capturing input."""

    def __init__(self, output: Iterable[str], returncode: int = 0) -> None:
        """Replay the given output lines and exit with the given code."""
        self.stdout: Iterator[str] = iter(output)
        self.stdin = io.StringIO()
        self.returncode = returncode
        self.terminated = False

    def wait(self) -> int:
        """Return the exit code immediately."""
        return self.returncode

    def terminate(self) -> None:
        """Record that the process was terminated."""
        self.terminated = True


def negotiation(*extra: str) -> list[str]:
    """Return SSH output where the server allocates a port and accepts the config."""
    return [
        "Allocated port 32123 for remote forward to localhost:8000\n",
        "SEND_CONFIGURATION\n",
        "RECEIVED_CONFIGURATION\n",
        *extra,
    ]


def sent_config(proc: FakeSSHProcess) -> dict[str, Any]:
    """Decode the tunnel config sent to the server, as the SSHD server does."""
    lines = proc.stdin.getvalue().splitlines()
    assert lines[-1] == "END_CONFIGURATION"
    data: dict[str, Any] = json.loads(base64.decodebytes("".join(lines[:-1]).encode()))
    return data


def test_configure_tunnel_minimal(
    make_connect_config: Callable[..., ConnectConfig],
) -> None:
    """
    Check that only the port and protocol are sent when nothing else is set.

    Older servers reject unknown options, so unset options must not be sent (#733).
    """
    proc = FakeSSHProcess(negotiation())
    tunnel.configure_tunnel(proc, make_connect_config())
    assert sent_config(proc) == {"allocated_port": 32123, "backend_protocol": "http"}


def test_configure_tunnel_all_options(
    make_connect_config: Callable[..., ConnectConfig],
) -> None:
    """Check that the configured options are sent to the server."""
    proc = FakeSSHProcess(negotiation())
    config = make_connect_config(
        backend_protocol="https",
        read_timeout=60,
        internal=True,
        auth_oidc_issuer="https://idp.example.invalid/realms/test",
        auth_oidc_client_id="client",
        auth_oidc_client_secret="secret",
        auth_oidc_allowed_groups=["admins"],
        auth_external_params={"tenancy-id": "abc"},
        tls_cert_data="Y2VydA==",
        tls_key_data="a2V5",
        tls_client_ca_data="Y2E=",
        liveness_path="/healthz",
    )
    tunnel.configure_tunnel(proc, config)
    assert sent_config(proc) == {
        "allocated_port": 32123,
        "backend_protocol": "https",
        "read_timeout": 60,
        "internal": True,
        "auth_oidc_issuer": "https://idp.example.invalid/realms/test",
        "auth_oidc_client_id": "client",
        "auth_oidc_client_secret": "secret",
        "auth_oidc_allowed_groups": ["admins"],
        "auth_external_params": {"tenancy-id": "abc"},
        "tls_cert": "Y2VydA==",
        "tls_key": "a2V5",
        "tls_client_ca": "Y2E=",
        "liveness_path": "/healthz",
        "liveness_period": 10,
        "liveness_failures": 3,
    }


def test_configure_tunnel_skip_auth(
    make_connect_config: Callable[..., ConnectConfig],
) -> None:
    """Check that auth options are not sent when auth is skipped."""
    proc = FakeSSHProcess(negotiation())
    config = make_connect_config(
        skip_auth=True,
        auth_oidc_issuer="https://idp.example.invalid",
        auth_external_params={"tenancy-id": "abc"},
    )
    tunnel.configure_tunnel(proc, config)
    assert sent_config(proc) == {
        "allocated_port": 32123,
        "backend_protocol": "http",
        "skip_auth": True,
    }


def test_configure_tunnel_forwards_server_output(
    make_connect_config: Callable[..., ConnectConfig],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Check that SSH and server messages during negotiation are shown to the user."""
    output = negotiation()
    output.insert(0, "Warning: Permanently added 'zenith' to known hosts.\n")
    output.insert(2, "Welcome to Zenith\n")
    tunnel.configure_tunnel(FakeSSHProcess(output), make_connect_config())
    captured = capsys.readouterr()
    assert "Permanently added" in captured.err
    assert "Welcome to Zenith" in captured.out


@pytest.fixture
def spawned(
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[..., list[dict[str, Any]]]:
    """Replace the SSH subprocess with fakes and record how each was spawned."""
    calls: list[dict[str, Any]] = []

    def setup(proc: FakeSSHProcess) -> list[dict[str, Any]]:
        """Make the next spawned SSH process the given fake."""

        def popen(command: list[str], **kwargs: Any) -> FakeSSHProcess:
            """Record the SSH command and the identity file it is given."""
            identity = pathlib.Path(command[command.index("-i") + 1])
            calls.append(
                {
                    "command": command,
                    "identity": identity,
                    "key": identity.read_bytes(),
                    "mode": stat.S_IMODE(identity.stat().st_mode),
                    "proc": proc,
                }
            )
            return proc

        monkeypatch.setattr(subprocess, "Popen", popen)
        return calls

    return setup


def test_create_ssh_command(
    spawned: Callable[..., list[dict[str, Any]]],
    make_connect_config: Callable[..., ConnectConfig],
) -> None:
    """Check that SSH forwards a dynamic remote port to the configured service."""
    calls = spawned(FakeSSHProcess(negotiation()))
    config = make_connect_config(
        server_port=2222, forward_to_host="app.local", forward_to_port=3000
    )
    with pytest.raises(SystemExit):
        tunnel.create(config)
    command = calls[0]["command"]
    assert command[0] == "ssh"
    assert command[-1] == "zenith@zenith.example.invalid"
    assert command[command.index("-R") + 1] == "0:app.local:3000"
    assert command[command.index("-p") + 1] == "2222"
    assert "-vvv" not in command


def test_create_debug_is_verbose(
    spawned: Callable[..., list[dict[str, Any]]],
    make_connect_config: Callable[..., ConnectConfig],
) -> None:
    """Check that SSH is made verbose, before the destination, in debug mode."""
    calls = spawned(FakeSSHProcess(negotiation()))
    with pytest.raises(SystemExit):
        tunnel.create(make_connect_config(debug=True))
    assert calls[0]["command"][-2] == "-vvv"


def test_create_writes_private_key(
    spawned: Callable[..., list[dict[str, Any]]],
    make_connect_config: Callable[..., ConnectConfig],
) -> None:
    """Check that SSH gets the decoded private key in a file only the user can read."""
    calls = spawned(FakeSSHProcess(negotiation()))
    config = make_connect_config()
    with pytest.raises(SystemExit):
        tunnel.create(config)
    assert calls[0]["key"] == base64.b64decode(config.ssh_private_key_data or "")
    assert calls[0]["mode"] == 0o600


def test_create_connected(
    spawned: Callable[..., list[dict[str, Any]]],
    make_connect_config: Callable[..., ConnectConfig],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Check that output is forwarded after connecting and a clean exit is reported."""
    calls = spawned(FakeSSHProcess(negotiation("Connection to zenith closed.\n")))
    with pytest.raises(SystemExit) as exc:
        tunnel.create(make_connect_config())
    assert exc.value.code == 0
    assert "Connection to zenith closed." in capsys.readouterr().out
    assert not calls[0]["identity"].exists()


class TimeoutOutput:
    """Yield the given lines then raise TimeoutError as the alarm would."""

    def __init__(self, lines: list[str]) -> None:
        """Store the lines to yield before timing out."""
        self.lines = lines

    def __iter__(self) -> Iterator[str]:
        """Yield the lines, then time out waiting for the next one."""
        yield from self.lines
        raise TimeoutError


@pytest.mark.parametrize(
    ("output", "returncode", "expected_code"),
    [
        (["zenith@zenith: Permission denied (publickey).\n"], 255, 1),
        (["ssh: connect to host zenith port 22: Connection refused\n"], 255, 1),
        (["Allocated port 32123 for remote forward to localhost:8000\n"], 255, 1),
        (negotiation()[:2], 255, 1),
        (TimeoutOutput(["Allocated port 32123 for remote forward\n"]), 0, 1),
        (negotiation("Timeout, server zenith not responding.\n"), 255, 255),
    ],
    ids=[
        "auth-failed",
        "connection-refused",
        "no-config-request",
        "config-not-acknowledged",
        "negotiation-timeout",
        "dropped-after-connect",
    ],
)
def test_create_connection_failure(
    output: Iterable[str],
    returncode: int,
    expected_code: int,
    spawned: Callable[..., list[dict[str, Any]]],
    make_connect_config: Callable[..., ConnectConfig],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Check that a failed or dropped connection exits non-zero and removes the key."""
    calls = spawned(FakeSSHProcess(output, returncode))
    with pytest.raises(SystemExit) as exc:
        tunnel.create(make_connect_config())
    assert exc.value.code == expected_code
    assert not calls[0]["identity"].exists()
    # SSH's own error messages must reach the user to diagnose the failure
    captured = capsys.readouterr()
    lines = output.lines if isinstance(output, TimeoutOutput) else output
    for line in lines:
        if not line.startswith(("Allocated port", "SEND_", "RECEIVED_")):
            assert line.strip() in captured.out + captured.err


def test_create_negotiation_timeout_terminates_ssh(
    spawned: Callable[..., list[dict[str, Any]]],
    make_connect_config: Callable[..., ConnectConfig],
) -> None:
    """Check that the SSH process is terminated if negotiation times out."""
    calls = spawned(FakeSSHProcess(TimeoutOutput([])))
    with pytest.raises(SystemExit):
        tunnel.create(make_connect_config())
    assert calls[0]["proc"].terminated


def test_create_drops_root(
    monkeypatch: pytest.MonkeyPatch,
    spawned: Callable[..., list[dict[str, Any]]],
    make_connect_config: Callable[..., ConnectConfig],
) -> None:
    """
    Check that, when run as root, the client switches user before spawning SSH.

    The container image starts as root and relies on this to run SSH unprivileged.
    """
    calls = spawned(FakeSSHProcess(negotiation()))
    switched: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "getuid", lambda: 0)
    monkeypatch.setattr(os, "setuid", lambda uid: switched.append((uid, len(calls))))
    with pytest.raises(SystemExit):
        tunnel.create(make_connect_config(run_as_user=1001))
    assert switched == [(1001, 0)]


def test_create_cannot_drop_privileges_as_non_root(
    monkeypatch: pytest.MonkeyPatch,
    spawned: Callable[..., list[dict[str, Any]]],
    make_connect_config: Callable[..., ConnectConfig],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Check that a non-root client warns and carries on as the current user."""
    calls = spawned(FakeSSHProcess(negotiation()))
    switched: list[int] = []
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    monkeypatch.setattr(os, "setuid", switched.append)
    with pytest.raises(SystemExit) as exc:
        tunnel.create(make_connect_config(run_as_user=1001))
    assert exc.value.code == 0
    assert switched == []
    assert len(calls) == 1
    assert "Cannot switch user" in caplog.text


@pytest.mark.usefixtures("restore_logging")
def test_cli_connect(
    tmp_path: pathlib.Path,
    ssh_key_file: pathlib.Path,
    spawned: Callable[..., list[dict[str, Any]]],
) -> None:
    """Check that CLI options override the config file without clearing other keys."""
    config_file = tmp_path / "connect.yaml"
    config_file.write_text("forward_to_port: 3000\nserver_port: 2222\ndebug: false\n")
    calls = spawned(FakeSSHProcess(negotiation()))
    result = CliRunner().invoke(
        main,
        [
            "connect",
            f"--config={config_file}",
            f"--ssh-identity-path={ssh_key_file}",
            "--server-address=zenith.example.invalid",
            "--server-port=2022",
            "--debug",
        ],
    )
    assert result.exit_code == 0, result.output
    command = calls[0]["command"]
    assert calls[0]["key"] == ssh_key_file.read_bytes()
    assert command[command.index("-R") + 1] == "0:localhost:3000"
    assert command[command.index("-p") + 1] == "2022"
    assert command[-2:] == ["-vvv", "zenith@zenith.example.invalid"]
