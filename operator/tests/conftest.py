"""Configure the environment and provide shared fixtures for the operator tests."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import easykube
import pytest

if TYPE_CHECKING:
    from zenith.operator.models import v1alpha1 as api

session_patch = pytest.MonkeyPatch()


def fake_kube_config(**kwargs: Any) -> easykube.Configuration:
    """Return an easykube configuration for an unreachable cluster."""
    return easykube.Configuration(
        base_url="https://kubernetes.example.invalid", **kwargs
    )


def pytest_configure(config: pytest.Config) -> None:
    """Provide the settings and Kubernetes config the operator loads on import."""
    session_patch.setenv(
        "ZENITH_OPERATOR__REGISTRAR_ADMIN_URL", "http://registrar.example.invalid"
    )
    session_patch.setenv("ZENITH_OPERATOR__SSHD_HOST", "sshd.example.invalid")
    session_patch.setenv("ZENITH_OPERATOR__SSHD_PORT", "2222")
    session_patch.delenv("ZENITH_OPERATOR_CONFIG", raising=False)
    session_patch.setattr(
        easykube.Configuration, "from_environment", staticmethod(fake_kube_config)
    )


def pytest_unconfigure(config: pytest.Config) -> None:
    """Undo the session-wide patches."""
    session_patch.undo()


def build_client(**spec: Any) -> api.Client:
    """Build Client ns/myclient with a minimal spec plus the given overrides."""
    from zenith.operator.models import v1alpha1 as api

    return api.Client.model_validate(
        {
            "apiVersion": "zenith.stackhpc.com/v1alpha1",
            "kind": "Client",
            "metadata": {"name": "myclient", "namespace": "ns", "uid": "abc"},
            "spec": {
                "reservationName": "res",
                "upstream": {"serviceName": "svc"},
                **spec,
            },
        }
    )


@pytest.fixture
def make_client() -> Callable[..., api.Client]:
    """Return a builder for Client resources."""
    return build_client
