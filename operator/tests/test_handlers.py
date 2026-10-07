"""Test the kopf handlers with fake Kubernetes and registrar backends."""

import base64
import functools
import hashlib
from collections.abc import Awaitable, Callable
from typing import Any, cast
from unittest import mock

import httpx
import kopf
import pytest
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from easykube import ApiError
from easykube.rest.util import PropertyDict
from zenith.operator import main
from zenith.operator.models import v1alpha1 as api

MakeClient = Callable[..., api.Client]

SERVICE_ACCOUNT = {
    "type": "ServiceAccount",
    "serviceAccount": {"clusterRoleName": "view"},
}


class FakeResource:
    """Stand in for an easykube resource with awaitable CRUD methods."""

    def __init__(self) -> None:
        """Create an async mock for each resource method."""
        self.fetch = mock.AsyncMock()
        self.create = mock.AsyncMock()
        self.replace = mock.AsyncMock(
            return_value={"metadata": {"resourceVersion": "2"}}
        )
        self.patch = mock.AsyncMock()
        self.delete = mock.AsyncMock()


class FakeApi:
    """Stand in for an easykube API that hands out resources from a shared store."""

    def __init__(self, resources: dict[str, FakeResource]) -> None:
        """Store the shared resource map."""
        self.resources = resources

    async def resource(self, name: str) -> FakeResource:
        """Return the fake resource with the given name."""
        return self.resources.setdefault(name, FakeResource())


class FakeKube:
    """Stand in for the operator's easykube client, keyed by resource name."""

    def __init__(self) -> None:
        """Create an empty resource store and object-level apply/delete mocks."""
        self.resources: dict[str, FakeResource] = {}
        self.apply_object = mock.AsyncMock()
        self.delete_object = mock.AsyncMock()

    def api(self, api_version: str) -> FakeApi:
        """Return an API backed by the shared resource store."""
        return FakeApi(self.resources)

    def resource(self, name: str) -> FakeResource:
        """Return the fake resource with the given name for test setup."""
        return self.resources.setdefault(name, FakeResource())

    def applied(self) -> dict[str, dict[str, Any]]:
        """Return the objects passed to apply_object keyed by kind."""
        return {c.args[0]["kind"]: c.args[0] for c in self.apply_object.call_args_list}

    def phases(self, resource: str) -> list[str]:
        """Return the phases saved to the given status resource, in order."""
        replace = self.resource(resource).replace
        return [c.args[1]["status"]["phase"] for c in replace.call_args_list]


class FakeRegistrar:
    """Record reserve requests and answer them like the registrar admin API."""

    def __init__(self) -> None:
        """Start with no requests and a successful response."""
        self.requests: list[httpx.Request] = []
        self.status_code = 200

    def handle(self, request: httpx.Request) -> httpx.Response:
        """Record the request and return a reserved subdomain."""
        self.requests.append(request)
        return httpx.Response(
            self.status_code,
            json={
                "subdomain": "abc123",
                "fqdn": "abc123.example.com",
                "fingerprints": ["SHA256:fp"],
            },
        )


@pytest.fixture
def kube(monkeypatch: pytest.MonkeyPatch) -> FakeKube:
    """Replace the operator's Kubernetes client with a fake."""
    fake = FakeKube()
    monkeypatch.setattr(main, "ekclient", fake)
    return fake


@pytest.fixture
def registrar(monkeypatch: pytest.MonkeyPatch) -> FakeRegistrar:
    """Route registrar HTTP requests to a fake."""
    fake = FakeRegistrar()
    transport = httpx.MockTransport(fake.handle)
    monkeypatch.setattr(
        httpx, "AsyncClient", functools.partial(httpx.AsyncClient, transport=transport)
    )
    return fake


def api_error(status_code: int) -> ApiError:
    """Build the error easykube raises for a Kubernetes API response."""
    request = httpx.Request("GET", "https://kubernetes.example.invalid")
    response = httpx.Response(status_code, request=request)
    return ApiError(httpx.HTTPStatusError("error", request=request, response=response))


def b64(value: str) -> str:
    """Base64-encode a string, as Kubernetes does for secret data."""
    return base64.b64encode(value.encode()).decode()


def body(resource: api.Client | api.Reservation) -> kopf.Body:
    """Return a resource as kopf would pass it to a handler."""
    return kopf.Body(resource.model_dump(by_alias=True, mode="json", exclude_none=True))


def make_reservation(phase: str = "Ready") -> api.Reservation:
    """Build Reservation ns/res in the given phase."""
    return api.Reservation.model_validate(
        {
            "apiVersion": "zenith.stackhpc.com/v1alpha1",
            "kind": "Reservation",
            "metadata": {"name": "res", "namespace": "ns", "uid": "def"},
            "spec": {"credentialSecretName": "creds"},
            "status": {"phase": phase},
        }
    )


def passthrough(*args: Any, **kwargs: Any) -> Callable[[Any], Any]:
    """Register nothing and return the handler unchanged."""
    return lambda handler: handler


async def test_model_handler_registers_and_validates(make_client: MakeClient) -> None:
    """
    Check that model_handler registers for the model and validates the body.

    kopf only routes events for the API group, version and plural it registered.
    """
    registered: list[tuple[Any, ...]] = []

    def register(*args: Any, **kwargs: Any) -> Callable[[Any], Any]:
        registered.append((*args, kwargs))
        return passthrough()

    func = mock.AsyncMock(return_value="result")
    handler = main.model_handler(api.Client, register, field="spec")(func)

    assert await handler(body=body(make_client())) == "result"
    assert registered == [
        ("zenith.stackhpc.com/v1alpha1", "clients", {"field": "spec"})
    ]
    assert isinstance(func.call_args.kwargs["instance"], api.Client)


async def test_model_handler_invalid_body_is_permanent() -> None:
    """
    Check that an invalid body is a permanent error.

    Retrying cannot fix an invalid resource, so kopf should stop rather than loop.
    """
    handler = main.model_handler(api.Client, passthrough)(mock.AsyncMock())
    with pytest.raises(kopf.PermanentError):
        await handler(body={"spec": {}})


@pytest.mark.parametrize(
    ("status_code", "expected"), [(409, kopf.TemporaryError), (500, ApiError)]
)
async def test_model_handler_api_errors(
    make_client: MakeClient, status_code: int, expected: type[Exception]
) -> None:
    """
    Check that conflicts are retried quickly and other API errors re-raised.

    A 409 means a stale resourceVersion, which normally succeeds on an immediate retry.
    """
    func = mock.AsyncMock(side_effect=api_error(status_code))
    handler = main.model_handler(api.Client, passthrough)(func)
    with pytest.raises(expected) as excinfo:
        await handler(instance=make_client())
    if isinstance(excinfo.value, kopf.TemporaryError):
        assert excinfo.value.delay == 5


async def reservation_changed(reservation: api.Reservation) -> None:
    """Invoke the reservation_changed handler for a reservation."""
    await main.reservation_changed(body=body(reservation), name="res", namespace="ns")


@pytest.mark.parametrize("phase", ["Ready", "Failed"])
async def test_reservation_changed_skips_finished(
    kube: FakeKube, registrar: FakeRegistrar, phase: str
) -> None:
    """
    Check that Ready and Failed reservations are left alone.

    Reprocessing a Ready reservation would reserve a second subdomain for it.
    """
    await reservation_changed(make_reservation(phase))
    assert kube.resources == {}
    assert registrar.requests == []


async def test_reservation_changed_reserves_subdomain(
    kube: FakeKube, registrar: FakeRegistrar
) -> None:
    """
    Check that a subdomain is reserved for the key and saved in the status.

    Clients wait for the reservation to be Ready before they are deployed.
    """
    kube.resource("secrets").fetch.return_value = PropertyDict(
        {"data": {"ssh-publickey": b64("ssh-ed25519 AAAA")}}
    )

    await reservation_changed(make_reservation("Unknown"))

    (request,) = registrar.requests
    assert str(request.url) == "http://registrar.example.invalid/admin/reserve"
    assert request.read() == b'{"public_keys":["ssh-ed25519 AAAA"]}'
    assert kube.phases("reservations/status") == ["Pending", "Ready"]
    status = kube.resource("reservations/status").replace.call_args.args[1]["status"]
    assert status == {
        "phase": "Ready",
        "subdomain": "abc123",
        "fqdn": "abc123.example.com",
        "fingerprint": "SHA256:fp",
    }


async def test_reservation_changed_generates_missing_keypair(
    kube: FakeKube, registrar: FakeRegistrar
) -> None:
    """
    Check that a missing keypair secret is generated and used to reserve.

    The reservation owns the secret so the key is deleted along with it.
    """
    secrets = kube.resource("secrets")
    secrets.fetch.side_effect = api_error(404)
    secrets.create.side_effect = lambda secret: PropertyDict(
        {"data": {k: b64(v) for k, v in secret["stringData"].items()}}
    )

    await reservation_changed(make_reservation("Pending"))

    (secret,) = secrets.create.call_args.args
    assert secret["metadata"]["name"] == "creds"
    assert secret["metadata"]["ownerReferences"][0]["uid"] == "def"
    public_key = secret["stringData"]["ssh-publickey"]
    load_ssh_public_key(public_key.encode())
    assert public_key in registrar.requests[0].read().decode()


async def test_reservation_changed_missing_public_key(
    kube: FakeKube, registrar: FakeRegistrar
) -> None:
    """Check that a credential secret without a public key is retried."""
    kube.resource("secrets").fetch.return_value = PropertyDict({"data": {}})
    with pytest.raises(kopf.TemporaryError):
        await reservation_changed(make_reservation("Pending"))
    assert registrar.requests == []


async def test_reservation_changed_registrar_failure(
    kube: FakeKube, registrar: FakeRegistrar
) -> None:
    """
    Check that a registrar failure raises and leaves the reservation not Ready.

    Marking it Ready without a subdomain would let clients deploy with no route.
    """
    kube.resource("secrets").fetch.return_value = PropertyDict(
        {"data": {"ssh-publickey": b64("key")}}
    )
    registrar.status_code = 500
    with pytest.raises(httpx.HTTPStatusError):
        await reservation_changed(make_reservation("Pending"))
    assert "Ready" not in kube.phases("reservations/status")


def setup_client_dependencies(
    kube: FakeKube,
    reservation_phase: str = "Ready",
    ports: list[dict[str, Any]] | None = None,
    private_key: str | None = "a2V5",
) -> None:
    """Make the service, reservation and credential a client needs available."""
    if ports is None:
        ports = [{"name": "http", "port": 80}, {"name": "metrics", "port": 9090}]
    kube.resource("services").fetch.return_value = PropertyDict(
        {"metadata": {"name": "svc", "namespace": "ns"}, "spec": {"ports": ports}}
    )
    kube.resource("reservations").fetch.return_value = body(
        make_reservation(reservation_phase)
    )
    data = {} if private_key is None else {"ssh-privatekey": private_key}
    kube.resource("secrets").fetch.return_value = PropertyDict({"data": data})


async def client_changed(client: api.Client) -> None:
    """Invoke the client_changed handler for a client."""
    await main.client_changed(body=body(client), name="myclient", namespace="ns")


def config_checksum(deployment: dict[str, Any]) -> str:
    """Return the config checksum annotation of a deployment's pod template."""
    annotations = deployment["spec"]["template"]["metadata"]["annotations"]
    checksum: str = annotations["zenith.stackhpc.com/config-checksum"]
    return checksum


async def test_client_changed_applies_resources(
    kube: FakeKube, make_client: MakeClient
) -> None:
    """
    Check that an owned secret and deployment are applied and the phase advances.

    Owner references let Kubernetes garbage collect them when the client is deleted.
    """
    setup_client_dependencies(kube)

    await client_changed(make_client())

    objects = kube.applied()
    assert set(objects) == {"Secret", "Deployment"}
    for obj in objects.values():
        assert obj["metadata"]["ownerReferences"][0]["kind"] == "Client"
    deleted = {c.args[0]["kind"] for c in kube.delete_object.call_args_list}
    assert deleted == {"ServiceAccount", "ClusterRoleBinding"}
    string_data = objects["Secret"]["stringData"]
    expected = hashlib.sha256(
        "".join(string_data[k] for k in sorted(string_data)).encode()
    ).hexdigest()
    assert config_checksum(objects["Deployment"]) == expected
    assert kube.phases("clients/status") == ["Pending", "ReservationReady"]


async def test_client_changed_rolls_deployment_on_new_key(
    kube: FakeKube, make_client: MakeClient
) -> None:
    """
    Check that the deployment checksum changes when the credential changes.

    Without a new checksum the pods keep running with the old credential.
    """
    checksums = []
    for key in ["a2V5MQ==", "a2V5Mg=="]:
        setup_client_dependencies(kube, private_key=key)
        await client_changed(make_client())
        checksums.append(config_checksum(kube.applied()["Deployment"]))
    assert checksums[0] != checksums[1]


async def test_client_changed_service_account_auth(
    kube: FakeKube, make_client: MakeClient
) -> None:
    """Check that ServiceAccount auth injection applies the account and binding."""
    setup_client_dependencies(kube)

    await client_changed(
        make_client(mitmProxy={"enabled": True, "authInject": SERVICE_ACCOUNT})
    )

    assert set(kube.applied()) == {
        "ServiceAccount",
        "ClusterRoleBinding",
        "Secret",
        "Deployment",
    }
    kube.delete_object.assert_not_called()


@pytest.mark.parametrize(
    ("port", "expected"), [(None, 80), (8443, 8443), ("metrics", 9090)]
)
async def test_client_changed_upstream_port(
    kube: FakeKube, make_client: MakeClient, port: int | str | None, expected: int
) -> None:
    """Check that the upstream port is the given number, the named port or the first."""
    setup_client_dependencies(kube)
    upstream: dict[str, Any] = {"serviceName": "svc"}
    if port is not None:
        upstream["port"] = port

    await client_changed(make_client(upstream=upstream))

    client_yaml = kube.applied()["Secret"]["stringData"]["client.yaml"]
    assert "forward_to_host: svc.ns.svc.cluster.local" in client_yaml
    assert f"forward_to_port: {expected}" in client_yaml


@pytest.mark.parametrize(
    ("setup", "port", "message"),
    [
        ({}, "nope", "named port"),
        ({"ports": []}, None, "any ports"),
        ({"reservation_phase": "Pending"}, None, "not ready"),
        ({"private_key": None}, None, "private key"),
    ],
    ids=["unknown-named-port", "no-ports", "reservation-pending", "no-private-key"],
)
async def test_client_changed_retries_until_ready(
    kube: FakeKube,
    make_client: MakeClient,
    setup: dict[str, Any],
    port: str | None,
    message: str,
) -> None:
    """
    Check that unusable dependencies are retried without applying anything.

    kopf retries TemporaryErrors, so the client deploys once the problem is fixed.
    """
    setup_client_dependencies(kube, **setup)
    upstream = {"serviceName": "svc", **({"port": port} if port else {})}
    with pytest.raises(kopf.TemporaryError, match=message):
        await client_changed(make_client(upstream=upstream))
    kube.apply_object.assert_not_called()


@pytest.mark.parametrize("missing", ["services", "reservations", "secrets"])
async def test_client_changed_missing_dependency(
    kube: FakeKube, make_client: MakeClient, missing: str
) -> None:
    """
    Check that a missing service, reservation or credential is retried.

    These may legitimately be created after the client that references them.
    """
    setup_client_dependencies(kube)
    kube.resource(missing).fetch.side_effect = api_error(404)
    with pytest.raises(kopf.TemporaryError):
        await client_changed(make_client())
    kube.apply_object.assert_not_called()


async def test_client_deleted_removes_cluster_role_binding(
    kube: FakeKube, make_client: MakeClient
) -> None:
    """
    Check that deleting a client deletes its cluster role binding.

    Kubernetes won't garbage collect it, as a Client can't own cluster objects.
    """
    client = make_client()
    await main.client_deleted(body=body(client), name="myclient", namespace="ns")
    kube.resource("clusterrolebindings").delete.assert_awaited_once_with(
        "zenith-client:ns:myclient"
    )


async def deployment_event(event_type: str, status: dict[str, Any]) -> None:
    """Invoke client_deployment_event for the deployment of ns/myclient."""
    # kopf types the decorated handler as needing every kwarg kopf would supply
    handler = cast(Callable[..., Awaitable[None]], main.client_deployment_event)
    await handler(
        type=event_type,
        namespace="ns",
        labels={"zenith.stackhpc.com/client": "myclient"},
        status=status,
    )


@pytest.mark.parametrize(
    ("event_type", "conditions", "phase"),
    [
        ("MODIFIED", [{"type": "Available", "status": "True"}], "Available"),
        ("MODIFIED", [{"type": "Available", "status": "False"}], "Unavailable"),
        ("ADDED", [{"type": "Progressing", "status": "True"}], "Unavailable"),
        ("ADDED", None, "Unavailable"),
        ("DELETED", [{"type": "Available", "status": "True"}], "Unknown"),
    ],
)
async def test_client_deployment_event_sets_phase(
    kube: FakeKube,
    event_type: str,
    conditions: list[dict[str, str]] | None,
    phase: str,
) -> None:
    """Check that the client is Available only when its deployment is Available."""
    await deployment_event(
        event_type, {} if conditions is None else {"conditions": conditions}
    )
    kube.resource("clients/status").patch.assert_awaited_once_with(
        "myclient", {"status": {"phase": phase}}, namespace="ns"
    )


async def test_client_deployment_event_ignores_deleted_client(kube: FakeKube) -> None:
    """
    Check that a 404 is ignored when the client has already gone.

    The deployment is deleted along with its client, so the client may not exist.
    """
    kube.resource("clients/status").patch.side_effect = api_error(404)
    await deployment_event("DELETED", {})


async def test_client_deployment_event_raises_other_errors(kube: FakeKube) -> None:
    """Check that errors other than 404 are raised when patching the status."""
    kube.resource("clients/status").patch.side_effect = api_error(500)
    with pytest.raises(ApiError):
        await deployment_event("DELETED", {})
