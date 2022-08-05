import base64
import dataclasses
import logging
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

import httpx

import kopf

import pydantic

from easykube import (
    Configuration,
    ApiError,
    ResourceSpec,
    resources as k8s
)

from .config import settings
from .models import v1alpha1 as api
from .template import default_loader
from .utils import mergeconcat


# Create an easykube client from the environment
from pydantic.json import pydantic_encoder
ekclient = Configuration.from_environment(json_encoder = pydantic_encoder).async_client()


# Load the CRDs and create easykube resource specs for them
reservation_crd = default_loader.load("crds/reservations.yaml")
Reservation = ResourceSpec.from_crd(reservation_crd)
ReservationStatus = dataclasses.replace(Reservation, name = f"{Reservation.name}/status")

client_crd = default_loader.load("crds/clients.yaml")
Client = ResourceSpec.from_crd(client_crd)
ClientStatus = dataclasses.replace(Client, name = f"{Client.name}/status")


logger = logging.getLogger(__name__)


@kopf.on.startup()
async def on_startup(**kwargs):
    """
    Runs on operator startup.
    """
    kopf_settings = kwargs["settings"]
    kopf_settings.persistence.finalizer = f"{settings.api_group}/finalizer"
    kopf_settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(
        prefix = settings.api_group
    )
    kopf_settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(
        prefix = settings.api_group,
        key = "last-handled-configuration",
    )
    try:
        # Create the CRDs
        await ekclient.apply_object(reservation_crd)
        await ekclient.apply_object(client_crd)
    except Exception as exc:
        logger.exception("error applying CRDs - exiting")
        sys.exit(1)


@kopf.on.cleanup()
async def on_cleanup(**kwargs):
    """
    Runs on operator shutdown.
    """
    await ekclient.aclose()


async def create_credential_secret(reservation, parent):
    """
    Creates a secret containing an SSH keypair for the given reservation with the specified
    parent as the owner.
    """
    private_key = Ed25519PrivateKey.generate()
    secret_data = {
        "metadata": {
            "name": reservation.spec.credential_secret_name,
            "labels": {
                "app.kubernetes.io/managed-by": "zenith-operator",
                "zenith.stackhpc.com/reservation": parent.metadata.name,
            },
        },
        "stringData": {
            reservation.spec.credential_secret_private_key_name: (
                private_key
                    .private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
                    .decode()
            ),
            reservation.spec.credential_secret_public_key_name: (
                private_key
                    .public_key()
                    .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
                    .decode()
            ),
        },
    }
    kopf.adopt(secret_data, parent)
    return await k8s.Secret(ekclient).create(secret_data)


@kopf.on.create(Reservation.api_version, Reservation.name)
async def reservation_changed(name, namespace, body, **kwargs):
    """
    Executes when a reservation is created.

    The spec of a reservation is immutable so we do not need to listen for updates.
    """
    reservation = api.Reservation.parse_obj(body)
    # If the reservation is Ready or Failed, there is nothing more to do
    if reservation.status.phase in {api.ReservationPhase.READY, api.ReservationPhase.FAILED}:
        return
    # Patch the reservation phase to acknowledge that we are aware of it
    if reservation.status.phase == api.ReservationPhase.UNKNOWN:
        _ = await ReservationStatus(ekclient).patch(
            name,
            { "status": { "phase": api.ReservationPhase.PENDING } },
            namespace = namespace
        )
    # Ensure that the referenced secret exists
    try:
        secret = await k8s.Secret(ekclient).fetch(
            reservation.spec.credential_secret_name,
            namespace = namespace
        )
    except ApiError as exc:
        if exc.status_code == 404:
            secret = await create_credential_secret(reservation, body)
        else:
            raise
    # Extract the public key from the secret and reserve a domain for it
    try:
        public_key_b64 = secret.data[reservation.spec.credential_secret_public_key_name]
    except KeyError:
        raise kopf.TemporaryError("unable to find public key data in secret")
    else:
        public_key = base64.b64decode(public_key_b64).decode()
    async with httpx.AsyncClient(base_url = settings.registrar_admin_url) as zclient:
        response = await zclient.post(
            "/admin/reserve",
            json = { "public_keys": [public_key] }
        )
        response.raise_for_status()
        response_data = response.json()
    # Patch the status to reflect the reserved subdomain
    status = api.ReservationStatus(
        phase = api.ReservationPhase.READY,
        subdomain = response_data["subdomain"],
        fqdn = response_data["fqdn"],
        fingerprint = response_data["fingerprints"][0]
    )
    _ = await ReservationStatus(ekclient).patch(
        name,
        { "status": status.dict() },
        namespace = namespace
    )


@kopf.on.create(Client.api_version, Client.name)
@kopf.on.update(Client.api_version, Client.name, field = "spec")
@kopf.on.resume(Client.api_version, Client.name)
async def client_changed(name, namespace, body, **kwargs):
    """
    Executes when a client is created or the spec of a client is updated.

    It also runs for each client when the operator is resumed and will update the
    client resources to match the new configuration.
    """
    try:
        client = api.Client.parse_obj(body)
    except pydantic.ValidationError as exc:
        raise kopf.PermanentError(str(exc))
    # Patch the phase to acknowledge that we are aware of the resource
    if client.status.phase == api.ClientPhase.UNKNOWN:
        client.status.phase = api.ClientPhase.PENDING
        _ = await ClientStatus(ekclient).patch(
            name,
            { "status": { "phase": client.status.phase } },
            namespace = namespace
        )
    # Make sure the specified service exists
    try:
        service = await k8s.Service(ekclient).fetch(
            client.spec.upstream.service_name,
            namespace = namespace
        )
    except ApiError as exc:
        if exc.status_code == 404:
            raise kopf.TemporaryError("could not find specified service")
        else:
            raise
    # Make sure the specified reservation exists
    try:
        reservation = await Reservation(ekclient).fetch(
            client.spec.reservation_name,
            namespace = namespace
        )
    except ApiError as exc:
        if exc.status_code == 404:
            raise kopf.TemporaryError("could not find specified reservation")
        else:
            raise
    # Wait for the specified reservation to become ready
    reservation = api.Reservation.parse_obj(reservation)
    if reservation.status.phase != api.ReservationPhase.READY:
        # This condition normally only takes a short time to resolve
        raise kopf.TemporaryError("specified reservation is not ready yet", delay = 5)
    # Once the reservation is ready, update the status to reflect that
    if client.status.phase == api.ClientPhase.PENDING:
        client.status.phase = api.ClientPhase.RESERVATION_READY
        _ = await ClientStatus(ekclient).patch(
            name,
            { "status": { "phase": client.status.phase } },
            namespace = namespace
        )
    # Get the credential associated with the reservation
    try:
        credential = await k8s.Secret(ekclient).fetch(
            reservation.spec.credential_secret_name,
            namespace = namespace
        )
    except ApiError as exc:
        if exc.status_code == 404:
            raise kopf.TemporaryError("could not find credential for reservation")
        else:
            raise
    # Extract the SSH private key data from the credential
    try:
        private_key_b64 = credential.data[reservation.spec.credential_secret_private_key_name]
    except KeyError:
        raise kopf.TemporaryError("unable to find private key data in reservation secret")
    # Derive the upstream host from the service
    upstream_host = "{}.{}.{}".format(
        service.metadata.name,
        service.metadata.namespace,
        settings.cluster_service_domain
    )
    # Derive the upstream port based on the specified port
    if client.spec.upstream.port:
        # If an integer port is given, use it as-is
        # If the port is given but is not an integer, treat it as a port name
        try:
            upstream_port = int(client.spec.upstream.port)
        except ValueError:
            try:
                upstream_port = next(
                    port["port"]
                    for port in service.spec.ports
                    if port["name"] == client.spec.upstream.port
                )
            except StopIteration:
                raise kopf.TemporaryError("named port does not exist for service")
    else:
        # If no port was given, use the first port
        try:
            upstream_port = service.spec.ports[0]["port"]
        except IndexError:
            raise kopf.TemporaryError("service does not have any ports")
    # Parameters for the template rendering
    params = dict(
        name = name,
        namespace = namespace,
        ssh_private_key_data = private_key_b64,
        upstream_host = upstream_host,
        upstream_port = upstream_port,
        client = client,
        # Merge any client-specific auth parameters with the defaults
        auth_params = mergeconcat(settings.default_auth_params, client.spec.auth.params)
    )
    # Decide whether we need the service account and cluster role and delete if not
    service_account = default_loader.load("client/serviceaccount.yaml", **params)
    kopf.adopt(service_account, body)
    cluster_role_binding = default_loader.load("client/clusterrolebinding.yaml", **params)
    if (
        client.spec.mitm_proxy.enabled and
        client.spec.mitm_proxy.auth_inject.type == api.MITMProxyAuthInjectType.SERVICE_ACCOUNT
    ):
        await ekclient.apply_object(service_account)
        await ekclient.apply_object(cluster_role_binding)
    else:
        await ekclient.delete_object(cluster_role_binding)
        await ekclient.delete_object(service_account)
    # Always render the secret and deployment
    secret = default_loader.load("client/secret.yaml", **params)
    kopf.adopt(secret, body)
    await ekclient.apply_object(secret)
    deployment = default_loader.load("client/deployment.yaml", **params)
    kopf.adopt(deployment, body)
    await ekclient.apply_object(deployment)


@kopf.on.delete(Client.api_version, Client.name)
async def client_deleted(name, namespace, **kwargs):
    """
    Executes when a client is deleted.
    """
    # Kubernetes does not allow cluster-scoped objects to be owned by namespace-scoped ones
    # So we have to manually clean up the clusterrolebinding object if it exists
    name = f"zenith-client:{namespace}:{name}"
    await k8s.ClusterRoleBinding(ekclient).delete(name)


@kopf.on.event(
    k8s.Deployment.api_version,
    k8s.Deployment.name,
    labels = { f"{settings.api_group}/client": kopf.PRESENT }
)
async def client_deployment_event(type, namespace, labels, status, **kwargs):
    """
    Executes when the deployment for a client changes.
    """
    # Derive the next phase for the client that owns the deployment
    if type == "DELETED":
        phase = api.ClientPhase.UNKNOWN
    else:
        try:
            condition = next(
                c
                for c in status.get("conditions", [])
                if c["type"] == "Available"
            )
        except StopIteration:
            phase = api.ClientPhase.UNAVAILABLE
        else:
            if condition["status"] == "True":
                phase = api.ClientPhase.AVAILABLE
            else:
                phase = api.ClientPhase.UNAVAILABLE
    try:
        _ = await ClientStatus(ekclient).patch(
            labels[f"{settings.api_group}/client"],
            { "status": { "phase": phase } },
            namespace = namespace
        )
    except ApiError as exc:
        if exc.status_code != 404:
            raise
