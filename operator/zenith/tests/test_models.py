"""
Tests for validation and defaults of the operator's CRD models.
"""

import pydantic
import pytest
from zenith.operator.models import v1alpha1 as api


def client_spec(**overrides):
    """
    Return a minimal valid Client spec dict with the given overrides.
    """
    spec = {"reservationName": "res", "upstream": {"serviceName": "svc"}}
    spec.update(overrides)
    return spec


@pytest.mark.parametrize(
    ("port", "expected"),
    [(80, "80"), ("8080", "8080"), ("http", "http")],
)
def test_upstream_port(port, expected):
    """
    Check that integer and named upstream ports are normalised to strings.
    """
    spec = api.UpstreamSpec.model_validate({"serviceName": "svc", "port": port})
    assert spec.port == expected


def test_upstream_port_is_optional():
    """
    Check that the upstream port defaults to None.
    """
    spec = api.UpstreamSpec.model_validate({"serviceName": "svc"})
    assert spec.port is None


@pytest.mark.parametrize("port", [0, -1, "0"])
def test_upstream_port_must_be_positive(port):
    """
    Check that zero and negative upstream ports are rejected.
    """
    with pytest.raises(pydantic.ValidationError):
        api.UpstreamSpec.model_validate({"serviceName": "svc", "port": port})


def test_client_spec_defaults():
    """
    Check the defaults of a minimal ClientSpec.
    """
    spec = api.ClientSpec.model_validate(client_spec())
    assert spec.upstream.scheme == api.UpstreamScheme.HTTP
    assert spec.replica_count == 1
    assert not spec.internal
    assert not spec.mitm_proxy.enabled
    assert spec.mitm_proxy.auth_inject.type == api.MITMProxyAuthInjectType.NONE
    assert not spec.auth.skip


def test_client_spec_requires_reservation_and_upstream():
    """
    Check that reservationName and upstream are required.
    """
    with pytest.raises(pydantic.ValidationError):
        api.ClientSpec.model_validate({"upstream": {"serviceName": "svc"}})
    with pytest.raises(pydantic.ValidationError):
        api.ClientSpec.model_validate({"reservationName": "res"})


@pytest.mark.parametrize("name", ["Upper", "under_score", "dot.ted"])
def test_client_spec_rejects_bad_names(name):
    """
    Check that invalid reservation names are rejected.
    """
    with pytest.raises(pydantic.ValidationError):
        api.ClientSpec.model_validate(client_spec(reservationName=name))


@pytest.mark.parametrize("auth_type", ["Basic", "Bearer"])
def test_auth_inject_requires_matching_config(auth_type):
    """
    Check that Basic and Bearer auth injection require their config block.
    """
    with pytest.raises(pydantic.ValidationError):
        api.MITMProxyAuthInjectSpec.model_validate({"type": auth_type})


def test_auth_inject_basic_defaults():
    """
    Check the default secret keys for Basic auth injection.
    """
    spec = api.MITMProxyAuthInjectSpec.model_validate(
        {"type": "Basic", "basic": {"secretName": "creds"}}
    )
    assert spec.basic.username_key == "username"
    assert spec.basic.password_key == "password"


def test_auth_inject_bearer_defaults():
    """
    Check the default key, header and prefix for Bearer auth injection.
    """
    spec = api.MITMProxyAuthInjectSpec.model_validate(
        {"type": "Bearer", "bearer": {"secretName": "creds"}}
    )
    assert spec.bearer.token_key == "token"
    assert spec.bearer.header_name == "Authorization"
    assert spec.bearer.header_prefix == "Bearer"


def test_auth_inject_service_account_requires_cluster_role():
    # The service account config is defaulted when missing, but the default has no
    # cluster role name, so the spec is invalid
    """
    Check that ServiceAccount auth injection needs a clusterRoleName.
    """
    with pytest.raises(pydantic.ValidationError):
        api.MITMProxyAuthInjectSpec.model_validate({"type": "ServiceAccount"})
    spec = api.MITMProxyAuthInjectSpec.model_validate(
        {"type": "ServiceAccount", "serviceAccount": {"clusterRoleName": "view"}}
    )
    assert spec.service_account.cluster_role_name == "view"


def test_reservation_spec_defaults():
    """
    Check the default key names in a ReservationSpec.
    """
    spec = api.ReservationSpec.model_validate({"credentialSecretName": "creds"})
    assert spec.credential_secret_public_key_name == "ssh-publickey"
    assert spec.credential_secret_private_key_name == "ssh-privatekey"


@pytest.mark.parametrize("name", ["Upper", "under_score", ""])
def test_reservation_spec_rejects_bad_secret_name(name):
    """
    Check that invalid credential secret names are rejected.
    """
    with pytest.raises(pydantic.ValidationError):
        api.ReservationSpec.model_validate({"credentialSecretName": name})


def test_status_defaults_to_unknown():
    """
    Check that a Client without a status has the Unknown phase.
    """
    body = {
        "apiVersion": "zenith.stackhpc.com/v1alpha1",
        "kind": "Client",
        "metadata": {"name": "x", "namespace": "ns"},
        "spec": client_spec(),
    }
    assert api.Client.model_validate(body).status.phase == api.ClientPhase.UNKNOWN
