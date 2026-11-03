"""Test validation and defaults of the Client and Reservation CRD models."""

from typing import Any

import pydantic
import pytest
from zenith.operator.models import v1alpha1 as api


def client_spec(**overrides: Any) -> dict[str, Any]:
    """Return a minimal valid Client spec with the given overrides."""
    return {"reservationName": "res", "upstream": {"serviceName": "svc"}, **overrides}


@pytest.mark.parametrize(
    ("port", "expected"),
    [(80, "80"), ("8080", "8080"), ("http", "http")],
)
def test_upstream_port_is_normalised(
    port: int | str | None, expected: str | None
) -> None:
    """Check that numeric and named upstream ports are normalised to strings."""
    spec = api.UpstreamSpec.model_validate({"serviceName": "svc", "port": port})
    assert spec.port == expected


def test_upstream_port_is_optional() -> None:
    """Check that the upstream port defaults to None."""
    assert api.UpstreamSpec.model_validate({"serviceName": "svc"}).port is None


@pytest.mark.xfail(
    strict=True,
    reason="UpstreamSpec.validate_port calls int(None), raising TypeError",
)
def test_upstream_port_accepts_explicit_null() -> None:
    """
    Check that an explicit null upstream port is accepted.

    Clients that serialise unset optional fields send null rather than omitting them.
    """
    spec = api.UpstreamSpec.model_validate({"serviceName": "svc", "port": None})
    assert spec.port is None


@pytest.mark.parametrize("port", [0, -1, "0"])
def test_upstream_port_must_be_positive(port: int | str) -> None:
    """Check that zero and negative upstream ports are rejected."""
    with pytest.raises(pydantic.ValidationError):
        api.UpstreamSpec.model_validate({"serviceName": "svc", "port": port})


def test_client_spec_defaults() -> None:
    """Check the defaults of a minimal Client spec."""
    spec = api.ClientSpec.model_validate(client_spec())
    assert spec.upstream.scheme == api.UpstreamScheme.HTTP
    assert spec.replica_count == 1
    assert not spec.internal
    assert not spec.auth.skip
    assert not spec.mitm_proxy.enabled
    assert spec.mitm_proxy.auth_inject.type == api.MITMProxyAuthInjectType.NONE


@pytest.mark.parametrize(
    "spec",
    [
        {"upstream": {"serviceName": "svc"}},
        {"reservationName": "res"},
        client_spec(reservationName="Upper"),
        client_spec(reservationName="under_score"),
        client_spec(upstream={"serviceName": "dot.ted"}),
    ],
    ids=[
        "missing-reservation",
        "missing-upstream",
        "uppercase-reservation",
        "underscore-reservation",
        "dotted-service",
    ],
)
def test_client_spec_rejects_invalid(spec: dict[str, Any]) -> None:
    """Check that missing fields and invalid names are rejected."""
    with pytest.raises(pydantic.ValidationError):
        api.ClientSpec.model_validate(spec)


@pytest.mark.parametrize("auth_type", ["Basic", "Bearer", "ServiceAccount"])
def test_auth_inject_requires_config(auth_type: str) -> None:
    """Check that auth injection types require their config block."""
    with pytest.raises(pydantic.ValidationError):
        api.MITMProxyAuthInjectSpec.model_validate({"type": auth_type})


def test_auth_inject_defaults() -> None:
    """Check the defaults for Basic and Bearer auth injection."""
    basic = api.MITMProxyAuthInjectSpec.model_validate(
        {"type": "Basic", "basic": {"secretName": "creds"}}
    ).basic
    assert basic is not None
    assert (basic.username_key, basic.password_key) == ("username", "password")
    bearer = api.MITMProxyAuthInjectSpec.model_validate(
        {"type": "Bearer", "bearer": {"secretName": "creds"}}
    ).bearer
    assert bearer is not None
    assert (bearer.token_key, bearer.header_name, bearer.header_prefix) == (
        "token",
        "Authorization",
        "Bearer",
    )


def test_reservation_spec_defaults() -> None:
    """Check the default SSH key names for a Reservation."""
    spec = api.ReservationSpec.model_validate({"credentialSecretName": "creds"})
    assert spec.credential_secret_public_key_name == "ssh-publickey"
    assert spec.credential_secret_private_key_name == "ssh-privatekey"


@pytest.mark.parametrize("name", ["", "Upper", "under_score"])
def test_reservation_spec_rejects_bad_secret_name(name: str) -> None:
    """Check that invalid credential secret names are rejected."""
    with pytest.raises(pydantic.ValidationError):
        api.ReservationSpec.model_validate({"credentialSecretName": name})


def test_status_defaults_to_unknown() -> None:
    """
    Check that a Client without a status is in the Unknown phase.

    Handlers use Unknown to spot resources they have not acknowledged yet.
    """
    client = api.Client.model_validate(
        {
            "apiVersion": "zenith.stackhpc.com/v1alpha1",
            "kind": "Client",
            "metadata": {"name": "x", "namespace": "ns"},
            "spec": client_spec(),
        }
    )
    assert client.status.phase == api.ClientPhase.UNKNOWN
