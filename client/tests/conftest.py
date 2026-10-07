"""Isolate the client tests from the environment and provide shared fixtures."""

from __future__ import annotations

import base64
import logging
import os
import pathlib
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from zenith.client.config import ConnectConfig

PRIVATE_KEY = b"fake private key\n"
PUBLIC_KEY = "ssh-ed25519 AAAAfake zenith-key"


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    """Ignore any client settings from the environment or /etc/zenith/client.yaml."""
    for name in list(os.environ):
        if name.upper().startswith("ZENITH_CLIENT"):
            monkeypatch.delenv(name)
    config_file = tmp_path / "client.yaml"
    config_file.write_text("{}\n")
    monkeypatch.setenv("ZENITH_CLIENT_CONFIG", str(config_file))


@pytest.fixture
def ssh_key_file(tmp_path: pathlib.Path) -> pathlib.Path:
    """Write a fake SSH key pair and return the path of the private key."""
    path = tmp_path / "id_zenith"
    path.write_bytes(PRIVATE_KEY)
    path.with_name(path.name + ".pub").write_text(PUBLIC_KEY + "\n")
    return path


@pytest.fixture
def make_connect_config() -> Callable[..., ConnectConfig]:
    """Return a factory for a valid connect config with the given overrides."""

    def make(**overrides: Any) -> ConnectConfig:
        """Build a connect config, using a fake private key unless one is given."""
        overrides.setdefault("server_address", "zenith.example.invalid")
        overrides.setdefault(
            "ssh_private_key_data", base64.b64encode(PRIVATE_KEY).decode()
        )
        return ConnectConfig(**overrides)

    return make


@pytest.fixture
def restore_logging() -> Iterator[None]:
    """Undo the logging config that the CLI applies to the root logger."""
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)
