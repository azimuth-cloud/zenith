"""Test validation of the client configuration."""

import base64
import pathlib
from collections.abc import Callable

import pydantic
import pytest
from zenith.client.config import ConnectConfig, InitConfig


def b64(path: pathlib.Path) -> str:
    """Return the base64-encoded content of a file."""
    return base64.b64encode(path.read_bytes()).decode()


def test_ssh_private_key_read_from_identity_path(ssh_key_file: pathlib.Path) -> None:
    """Check that the private key is read from the identity path if not given."""
    config = ConnectConfig(
        server_address="zenith.example.invalid", ssh_identity_path=ssh_key_file
    )
    assert config.ssh_private_key_data == b64(ssh_key_file)


def test_ssh_private_key_required() -> None:
    """Check that a config without any SSH private key is rejected."""
    with pytest.raises(pydantic.ValidationError, match="No SSH private key"):
        ConnectConfig(server_address="zenith.example.invalid")


def test_tls_files_read_as_base64(
    tmp_path: pathlib.Path, make_connect_config: Callable[..., ConnectConfig]
) -> None:
    """Check that the TLS cert, key and client CA files are sent as base64 data."""
    paths = {}
    for name in ["cert", "key", "client_ca"]:
        paths[name] = tmp_path / f"{name}.pem"
        paths[name].write_text(f"{name} data\n")
    config = make_connect_config(
        tls_cert_file=paths["cert"],
        tls_key_file=paths["key"],
        tls_client_ca_file=paths["client_ca"],
    )
    assert config.tls_cert_data == b64(paths["cert"])
    assert config.tls_key_data == b64(paths["key"])
    assert config.tls_client_ca_data == b64(paths["client_ca"])


def test_tls_key_required_with_cert(
    make_connect_config: Callable[..., ConnectConfig],
) -> None:
    """Check that a TLS cert without a key is rejected."""
    with pytest.raises(pydantic.ValidationError, match="TLS key is required"):
        make_connect_config(tls_cert_data="Y2VydA==")


def test_allowed_groups_from_env(
    monkeypatch: pytest.MonkeyPatch, make_connect_config: Callable[..., ConnectConfig]
) -> None:
    """Check that allowed groups can be given as a comma-separated env var."""
    monkeypatch.setenv("ZENITH_CLIENT__AUTH_OIDC_ALLOWED_GROUPS", "admins,/org/devs")
    config = make_connect_config()
    assert config.auth_oidc_allowed_groups == ["admins", "/org/devs"]


def test_external_auth_params_from_env(
    monkeypatch: pytest.MonkeyPatch, make_connect_config: Callable[..., ConnectConfig]
) -> None:
    """
    Check that underscores in auth param names from env vars become hyphens.

    Env var names cannot contain hyphens, but the auth params keys must use them.
    """
    monkeypatch.setenv("ZENITH_CLIENT__AUTH_EXTERNAL_PARAMS__TENANCY_ID", "abc123")
    config = make_connect_config()
    assert config.auth_external_params == {"tenancy-id": "abc123"}


@pytest.mark.parametrize("key", ["Tenancy", "1st", "trailing-", "x"])
def test_external_auth_params_invalid_key(
    key: str, make_connect_config: Callable[..., ConnectConfig]
) -> None:
    """Check that auth param keys that the server would reject are rejected."""
    with pytest.raises(pydantic.ValidationError):
        make_connect_config(auth_external_params={key: "value"})


def test_registrar_url_trailing_slash_stripped(tmp_path: pathlib.Path) -> None:
    """
    Check that trailing slashes are removed from the registrar URL.

    Otherwise the client posts to '//associate', which the registrar rejects.
    """
    config = InitConfig(
        ssh_identity_path=tmp_path / "id_zenith",
        registrar_url="https://registrar.example.invalid/",
        token="token",
    )
    assert config.registrar_url == "https://registrar.example.invalid"
