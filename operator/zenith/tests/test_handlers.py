"""
Tests for the kopf handlers in zenith.operator.main, with easykube mocked.
"""

import base64
import hashlib
from unittest import mock

import kopf
import pytest
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from easykube import ApiError
from zenith.operator import main
from zenith.operator.models import v1alpha1 as api

from .helpers import make_client, make_reservation, to_body

SERVICE_ACCOUNT = {
    "type": "ServiceAccount",
    "serviceAccount": {"clusterRoleName": "view"},
}


def api_error(status_code):
    """
    Build an easykube ApiError with the given status code.
    """
    exc = ApiError.__new__(ApiError)
    Exception.__init__(exc, f"status {status_code}")
    exc.response = mock.Mock(status_code=status_code)
    exc.status_code = status_code
    return exc


def obj(**kwargs):
    """
    Return an attribute-accessible dict, like the objects returned by easykube.
    """
    from easykube.rest.util import PropertyDict

    return PropertyDict(kwargs)


def b64(value):
    """
    Base64-encode a string, as Kubernetes does for secret data.
    """
    return base64.b64encode(value.encode()).decode()


# model_handler


async def test_model_handler_injects_validated_instance():
    """
    Check that model_handler registers the handler and injects a validated instance.
    """
    func = mock.AsyncMock(return_value="result")
    registered = {}

    def register_fn(api_version, plural, **kwargs):
        registered.update(api_version=api_version, plural=plural, kwargs=kwargs)
        return lambda handler: handler

    handler = main.model_handler(api.Client, register_fn, field="spec")(func)
    body = to_body(make_client())

    assert await handler(body=body, name="x") == "result"
    assert registered == {
        "api_version": "zenith.stackhpc.com/v1alpha1",
        "plural": "clients",
        "kwargs": {"field": "spec"},
    }
    instance = func.call_args.kwargs["instance"]
    assert isinstance(instance, api.Client)
    assert instance.spec.reservation_name == "res"


async def test_model_handler_invalid_body_is_permanent_error():
    """
    Check that an invalid body becomes a kopf PermanentError.
    """
    handler = main.model_handler(api.Client, lambda *a, **k: lambda f: f)(
        mock.AsyncMock()
    )
    with pytest.raises(kopf.PermanentError):
        await handler(body={"spec": {}})


async def test_model_handler_conflict_is_retried_quickly():
    """
    Check that a 409 becomes a TemporaryError with a 5s delay.
    """
    func = mock.AsyncMock(side_effect=api_error(409))
    handler = main.model_handler(api.Client, lambda *a, **k: lambda f: f)(func)
    with pytest.raises(kopf.TemporaryError) as excinfo:
        await handler(instance=make_client())
    assert excinfo.value.delay == 5


async def test_model_handler_other_api_errors_propagate():
    """
    Check that non-409 API errors are re-raised.
    """
    func = mock.AsyncMock(side_effect=api_error(500))
    handler = main.model_handler(api.Client, lambda *a, **k: lambda f: f)(func)
    with pytest.raises(ApiError):
        await handler(instance=make_client())


# save_instance_status


async def test_save_instance_status(ekclient):
    """
    Check the status is replaced with the resourceVersion and the new one stored.
    """
    instance = make_client()
    instance.metadata.resource_version = "1"
    instance.status.phase = api.ClientPhase.PENDING
    status = ekclient.get_resource("clients/status")
    status.replace.return_value = {"metadata": {"resourceVersion": "2"}}

    await main.save_instance_status(instance)

    status.replace.assert_awaited_once_with(
        "myclient",
        {"metadata": {"resourceVersion": "1"}, "status": {"phase": "Pending"}},
        namespace="ns",
    )
    assert instance.metadata.resource_version == "2"


# create_credential_secret


async def test_create_credential_secret(ekclient):
    """
    Check that a valid, owned SSH keypair secret is created.
    """
    reservation = make_reservation()
    parent = kopf.Body(to_body(reservation))
    secrets = ekclient.get_resource("secrets")

    await main.create_credential_secret(reservation, parent)

    (secret,) = secrets.create.call_args.args
    assert secret["metadata"]["name"] == "creds"
    assert secret["metadata"]["ownerReferences"][0]["uid"] == "def"
    assert secret["metadata"]["labels"]["zenith.stackhpc.com/reservation"] == "res"
    string_data = secret["stringData"]
    assert string_data["ssh-privatekey"].startswith("-----BEGIN OPENSSH PRIVATE KEY")
    assert load_ssh_public_key(string_data["ssh-publickey"].encode())


# reservation_changed


async def call_reservation_changed(reservation):
    """
    Invoke the reservation_changed handler for a reservation.
    """
    await main.reservation_changed(
        body=kopf.Body(to_body(reservation)),
        name=reservation.metadata.name,
        namespace=reservation.metadata.namespace,
    )


@pytest.fixture
def registrar():
    """
    Mock the registrar HTTP client used to reserve a subdomain.
    """
    response = mock.Mock()
    response.json.return_value = {
        "subdomain": "abc123",
        "fqdn": "abc123.example.com",
        "fingerprints": ["SHA256:fp"],
    }
    zclient = mock.MagicMock()
    zclient.post = mock.AsyncMock(return_value=response)
    zclient.__aenter__ = mock.AsyncMock(return_value=zclient)
    zclient.__aexit__ = mock.AsyncMock(return_value=False)
    with mock.patch.object(main.httpx, "AsyncClient", return_value=zclient) as cls:
        zclient.cls = cls
        zclient.response = response
        yield zclient


@pytest.mark.parametrize("phase", ["Ready", "Failed"])
async def test_reservation_changed_skips_finished_reservations(ekclient, phase):
    """
    Check that Ready and Failed reservations are left alone.
    """
    await call_reservation_changed(make_reservation(phase=phase))
    ekclient.api.assert_not_called()


async def test_reservation_changed_reserves_with_existing_secret(ekclient, registrar):
    """
    Check the reserve call and Pending then Ready status updates.
    """
    ekclient.get_resource("reservations/status").replace.return_value = {
        "metadata": {"resourceVersion": "2"}
    }
    ekclient.get_resource("secrets").fetch.return_value = obj(
        data={"ssh-publickey": b64("ssh-ed25519 AAAA")}
    )

    await call_reservation_changed(make_reservation(phase="Unknown"))

    registrar.cls.assert_called_once_with(base_url="http://registrar.example.invalid/")
    registrar.post.assert_awaited_once_with(
        "/admin/reserve", json={"public_keys": ["ssh-ed25519 AAAA"]}
    )
    replace = ekclient.get_resource("reservations/status").replace
    # Pending is recorded first, then Ready with the reserved details
    phases = [call.args[1]["status"]["phase"] for call in replace.call_args_list]
    assert phases == ["Pending", "Ready"]
    assert replace.call_args.args[1]["status"] == {
        "phase": "Ready",
        "subdomain": "abc123",
        "fqdn": "abc123.example.com",
        "fingerprint": "SHA256:fp",
    }


async def test_reservation_changed_creates_missing_secret(ekclient, registrar):
    """
    Check that a missing credential secret is created before reserving.
    """
    ekclient.get_resource("reservations/status").replace.return_value = {
        "metadata": {"resourceVersion": "2"}
    }
    secrets = ekclient.get_resource("secrets")
    secrets.fetch.side_effect = api_error(404)
    secrets.create.return_value = obj(data={"ssh-publickey": b64("ssh-ed25519 NEW")})

    await call_reservation_changed(make_reservation(phase="Pending"))

    secrets.create.assert_awaited_once()
    registrar.post.assert_awaited_once_with(
        "/admin/reserve", json={"public_keys": ["ssh-ed25519 NEW"]}
    )


async def test_reservation_changed_missing_public_key(ekclient, registrar):
    """
    Check that a secret without a public key raises a TemporaryError.
    """
    ekclient.get_resource("secrets").fetch.return_value = obj(data={})
    with pytest.raises(kopf.TemporaryError):
        await call_reservation_changed(make_reservation(phase="Pending"))
    registrar.post.assert_not_called()


async def test_reservation_changed_registrar_failure_propagates(ekclient, registrar):
    """
    Check that a registrar failure propagates and the status is not updated.
    """
    ekclient.get_resource("secrets").fetch.return_value = obj(
        data={"ssh-publickey": b64("key")}
    )
    registrar.response.raise_for_status.side_effect = RuntimeError("boom")
    with pytest.raises(RuntimeError):
        await call_reservation_changed(make_reservation(phase="Pending"))
    ekclient.get_resource("reservations/status").replace.assert_not_called()


# client_changed


def service(ports=None):
    """
    Build a fake Service with the given ports.
    """
    if ports is None:
        ports = [{"name": "http", "port": 80}, {"name": "metrics", "port": 9090}]
    return obj(metadata=obj(name="svc", namespace="ns"), spec=obj(ports=ports))


def setup_client_resources(ekclient, reservation=None, svc=None, private_key="a2V5"):
    """
    Configure the mocked service, reservation, secret and status resources.
    """
    ekclient.get_resource("services").fetch.return_value = svc or service()
    reservation = reservation or make_reservation()
    ekclient.get_resource("reservations").fetch.return_value = to_body(reservation)
    ekclient.get_resource("secrets").fetch.return_value = obj(
        data={"ssh-privatekey": private_key}
    )
    ekclient.get_resource("clients/status").replace.return_value = {
        "metadata": {"resourceVersion": "2"}
    }


async def call_client_changed(client):
    """
    Invoke the client_changed handler for a client.
    """
    await main.client_changed(
        body=kopf.Body(to_body(client)),
        name=client.metadata.name,
        namespace=client.metadata.namespace,
    )


def applied(ekclient):
    """
    Return the objects applied via apply_object, keyed by kind.
    """
    return {c.args[0]["kind"]: c.args[0] for c in ekclient.apply_object.call_args_list}


async def test_client_changed_applies_secret_and_deployment(ekclient):
    """
    Check the applied objects, ownership, cleanup, checksum and phase progression.
    """
    setup_client_resources(ekclient)

    await call_client_changed(make_client(upstream={"serviceName": "svc"}))

    objects = applied(ekclient)
    assert set(objects) == {"Secret", "Deployment"}
    # Everything is owned by the client
    for o in objects.values():
        assert o["metadata"]["ownerReferences"][0]["kind"] == "Client"
    # Without the service account auth, the SA and CRB are cleaned up
    deleted = {c.args[0]["kind"] for c in ekclient.delete_object.call_args_list}
    assert deleted == {"ServiceAccount", "ClusterRoleBinding"}
    # The deployment carries a checksum of the secret data
    secret = objects["Secret"]
    expected = hashlib.sha256(
        "".join(secret["stringData"][k] for k in sorted(secret["stringData"])).encode()
    ).hexdigest()
    annotations = objects["Deployment"]["spec"]["template"]["metadata"]["annotations"]
    assert annotations["zenith.stackhpc.com/config-checksum"] == expected
    # The phase is advanced through Pending to ReservationReady
    phases = [
        c.args[1]["status"]["phase"]
        for c in ekclient.get_resource("clients/status").replace.call_args_list
    ]
    assert phases == ["Pending", "ReservationReady"]


async def test_client_changed_applies_service_account_for_sa_auth(ekclient):
    """
    Check the ServiceAccount and ClusterRoleBinding are applied for ServiceAccount auth.
    """
    setup_client_resources(ekclient)
    client = make_client(
        mitmProxy={"enabled": True, "authInject": SERVICE_ACCOUNT},
    )

    await call_client_changed(client)

    assert set(applied(ekclient)) == {
        "ServiceAccount",
        "ClusterRoleBinding",
        "Secret",
        "Deployment",
    }
    ekclient.delete_object.assert_not_called()


async def test_client_changed_checksum_follows_secret_content(ekclient):
    """
    Check that the deployment checksum changes when the secret content changes.
    """

    def checksum():
        deployment = applied(ekclient)["Deployment"]
        return deployment["spec"]["template"]["metadata"]["annotations"][
            "zenith.stackhpc.com/config-checksum"
        ]

    setup_client_resources(ekclient, private_key="a2V5MQ==")
    await call_client_changed(make_client())
    first = checksum()
    ekclient.apply_object.reset_mock()
    setup_client_resources(ekclient, private_key="a2V5Mg==")
    await call_client_changed(make_client())
    assert checksum() != first


@pytest.mark.parametrize(
    ("port", "expected"),
    [(None, 80), (8443, 8443), ("metrics", 9090)],
)
async def test_client_changed_upstream_port(ekclient, port, expected):
    """
    Check upstream port resolution for unset, numeric and named ports.
    """
    setup_client_resources(ekclient)
    upstream = {"serviceName": "svc"}
    if port is not None:
        upstream["port"] = port

    await call_client_changed(make_client(upstream=upstream))

    secret = applied(ekclient)["Secret"]
    assert f"forward_to_port: {expected}" in secret["stringData"]["client.yaml"]
    assert (
        "forward_to_host: svc.ns.svc.cluster.local"
        in (secret["stringData"]["client.yaml"])
    )


async def test_client_changed_unknown_named_port(ekclient):
    """
    Check that an unknown named port raises a TemporaryError.
    """
    setup_client_resources(ekclient)
    with pytest.raises(kopf.TemporaryError, match="named port"):
        await call_client_changed(
            make_client(upstream={"serviceName": "svc", "port": "nope"})
        )
    ekclient.apply_object.assert_not_called()


async def test_client_changed_service_without_ports(ekclient):
    """
    Check that a service with no ports raises a TemporaryError.
    """
    setup_client_resources(ekclient, svc=service(ports=[]))
    with pytest.raises(kopf.TemporaryError, match="any ports"):
        await call_client_changed(make_client())


@pytest.mark.parametrize("missing", ["services", "reservations", "secrets"])
async def test_client_changed_missing_dependency_is_retried(ekclient, missing):
    """
    Check that a missing service, reservation or secret is retried.
    """
    setup_client_resources(ekclient)
    ekclient.get_resource(missing).fetch.side_effect = api_error(404)
    with pytest.raises(kopf.TemporaryError):
        await call_client_changed(make_client())
    ekclient.apply_object.assert_not_called()


async def test_client_changed_waits_for_ready_reservation(ekclient):
    """
    Check that a reservation that is not Ready is retried after 5s.
    """
    setup_client_resources(ekclient, reservation=make_reservation(phase="Pending"))
    with pytest.raises(kopf.TemporaryError) as excinfo:
        await call_client_changed(make_client())
    assert excinfo.value.delay == 5
    ekclient.apply_object.assert_not_called()


async def test_client_changed_missing_private_key(ekclient):
    """
    Check that a credential without a private key raises a TemporaryError.
    """
    setup_client_resources(ekclient)
    ekclient.get_resource("secrets").fetch.return_value = obj(data={})
    with pytest.raises(kopf.TemporaryError, match="private key"):
        await call_client_changed(make_client())


async def test_client_changed_other_api_errors_propagate(ekclient):
    """
    Check that unexpected API errors are re-raised.
    """
    setup_client_resources(ekclient)
    ekclient.get_resource("services").fetch.side_effect = api_error(500)
    with pytest.raises(ApiError):
        await call_client_changed(make_client())


# client_deleted


async def test_client_deleted_removes_cluster_role_binding(ekclient):
    """
    Check that deleting a client deletes its ClusterRoleBinding.
    """
    await main.client_deleted(
        body=to_body(make_client()),
        name="myclient",
        namespace="ns",
    )
    ekclient.api.assert_called_with("rbac.authorization.k8s.io/v1")
    ekclient.get_resource("clusterrolebindings").delete.assert_awaited_once_with(
        "zenith-client:ns:myclient"
    )


# client_deployment_event


async def deployment_event(ekclient, event_type, status, patch_error=None):
    """
    Invoke client_deployment_event and return the client status resource.
    """
    resource = ekclient.get_resource("clients/status")
    if patch_error:
        resource.patch.side_effect = patch_error
    await main.client_deployment_event(
        type=event_type,
        namespace="ns",
        labels={"zenith.stackhpc.com/client": "myclient"},
        status=status,
    )
    return resource


@pytest.mark.parametrize(
    ("event_type", "status", "phase"),
    [
        (
            "MODIFIED",
            {"conditions": [{"type": "Available", "status": "True"}]},
            "Available",
        ),
        (
            "MODIFIED",
            {"conditions": [{"type": "Available", "status": "False"}]},
            "Unavailable",
        ),
        (
            "ADDED",
            {"conditions": [{"type": "Progressing", "status": "True"}]},
            "Unavailable",
        ),
        ("ADDED", {}, "Unavailable"),
        (
            "DELETED",
            {"conditions": [{"type": "Available", "status": "True"}]},
            "Unknown",
        ),
    ],
)
async def test_client_deployment_event_sets_phase(ekclient, event_type, status, phase):
    """
    Check the client phase derived from deployment events.
    """
    resource = await deployment_event(ekclient, event_type, status)
    resource.patch.assert_awaited_once_with(
        "myclient", {"status": {"phase": phase}}, namespace="ns"
    )


async def test_client_deployment_event_ignores_missing_client(ekclient):
    """
    Check that a 404 when patching the client status is ignored.
    """
    await deployment_event(ekclient, "DELETED", {}, patch_error=api_error(404))


async def test_client_deployment_event_raises_other_errors(ekclient):
    """
    Check that non-404 errors patching the status are raised.
    """
    with pytest.raises(ApiError):
        await deployment_event(ekclient, "MODIFIED", {}, patch_error=api_error(500))
