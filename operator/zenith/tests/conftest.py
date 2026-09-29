"""
Pytest configuration and fixtures for the operator tests.
"""

import os

# The operator builds its settings and easykube client at import time, so the
# environment must be populated before anything from zenith.operator is imported
os.environ["ZENITH_OPERATOR__REGISTRAR_ADMIN_URL"] = "http://registrar.example.invalid"
os.environ["ZENITH_OPERATOR__SSHD_HOST"] = "sshd.example.invalid"
os.environ["ZENITH_OPERATOR__SSHD_PORT"] = "2222"
os.environ.pop("ZENITH_OPERATOR_CONFIG", None)

from unittest import mock

import pytest


@pytest.fixture
def ekclient():
    """
    Patch the operator's easykube client (main.ekclient) with a mock.

    ``ekclient.api(...).resource(...)`` returns a per-resource-name mock (available
    as ``ekclient.resources[name]``) so tests can configure each resource.
    """
    from zenith.operator import main

    client = mock.MagicMock()
    client.apply_object = mock.AsyncMock()
    client.delete_object = mock.AsyncMock()
    resources = {}

    def get_resource(name):
        if name not in resources:
            resources[name] = mock.MagicMock()
            for method in ("fetch", "create", "replace", "patch", "delete"):
                setattr(resources[name], method, mock.AsyncMock())
        return resources[name]

    async def resource(name):
        return get_resource(name)

    client.resources = resources
    client.get_resource = get_resource
    client.api.return_value.resource = resource
    with mock.patch.object(main, "ekclient", client):
        yield client
