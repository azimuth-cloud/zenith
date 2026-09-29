"""
Shared builders for operator test resources.
"""

from zenith.operator.models import v1alpha1 as api


def make_client(name="myclient", namespace="ns", **spec_overrides):
    """
    Build a Client resource with the given spec overrides.
    """
    spec = {"reservationName": "res", "upstream": {"serviceName": "svc"}}
    spec.update(spec_overrides)
    return api.Client.model_validate(
        {
            "apiVersion": "zenith.stackhpc.com/v1alpha1",
            "kind": "Client",
            "metadata": {"name": name, "namespace": namespace, "uid": "abc"},
            "spec": spec,
        }
    )


def make_reservation(name="res", namespace="ns", phase="Ready", **status):
    """
    Build a Reservation resource in the given phase.
    """
    return api.Reservation.model_validate(
        {
            "apiVersion": "zenith.stackhpc.com/v1alpha1",
            "kind": "Reservation",
            "metadata": {"name": name, "namespace": namespace, "uid": "def"},
            "spec": {"credentialSecretName": "creds"},
            "status": {"phase": phase, **status},
        }
    )


def to_body(resource):
    """
    Return the body of a resource as kopf would supply it (camelCase dict).
    """
    return resource.model_dump(by_alias=True, mode="json", exclude_none=True)
