import base64
import functools
import hashlib
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

from easykube import Configuration, ApiError
from kube_custom_resource import CustomResourceRegistry

from . import models
from .config import settings
from .models import v1alpha1 as api
from .template import default_loader
from .utils import mergeconcat


logger = logging.getLogger(__name__)


# Create an easykube client from the environment
from pydantic.json import pydantic_encoder
ekclient = Configuration.from_environment(json_encoder = pydantic_encoder).async_client()


# Create a registry of custom resources and populate it from the models module
registry = CustomResourceRegistry(settings.api_group, settings.crd_categories)
registry.discover_models(models)


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
        for crd in registry:
            await ekclient.apply_object(crd.kubernetes_resource(), force = True)
    except Exception:
        logger.exception("error applying CRDs - exiting")
        sys.exit(1)


@kopf.on.cleanup()
async def on_cleanup(**kwargs):
    """
    Runs on operator shutdown.
    """
    await ekclient.aclose()


async def ekresource_for_model(model, subresource = None):
    """
    Returns an easykube resource for the given model.
    """
    api = ekclient.api(f"{settings.api_group}/{model._meta.version}")
    resource = model._meta.plural_name
    if subresource:
        resource = f"{resource}/{subresource}"
    return await api.resource(resource)


async def save_instance_status(instance):
    """
    Save the status of this addon using the given easykube client.
    """
    ekresource = await ekresource_for_model(instance, "status")
    data = await ekresource.replace(
        instance.metadata.name,
        {
            # Include the resource version for optimistic concurrency
            "metadata": { "resourceVersion": instance.metadata.resource_version },
            "status": instance.status.dict(exclude_defaults = True),
        },
        namespace = instance.metadata.namespace
    )
    # Store the new resource version
    instance.metadata.resource_version = data["metadata"]["resourceVersion"]


def model_handler(model, register_fn, /, **kwargs):
    """
    Decorator that registers a handler with kopf for the specified model.
    """
    api_version = f"{settings.api_group}/{model._meta.version}"
    def decorator(func):
        @functools.wraps(func)
        async def handler(**handler_kwargs):
            if "instance" not in handler_kwargs:
                try:
                    handler_kwargs["instance"] = model.model_validate(handler_kwargs["body"])
                except pydantic.ValidationError as exc:
                    raise kopf.PermanentError(str(exc))
            try:
                return await func(**handler_kwargs)
            except ApiError as exc:
                if exc.status_code == 409:
                    # When a handler fails with a 409, we want to retry quickly
                    raise kopf.TemporaryError(str(exc), delay = 5)
                else:
                    raise
        return register_fn(api_version, model._meta.plural_name, **kwargs)(handler)
    return decorator


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
    secrets = await ekclient.api("v1").resource("secrets")
    return await secrets.create(secret_data)


@model_handler(api.Reservation, kopf.on.create)
async def reservation_changed(instance, name, namespace, body, **kwargs):
    """
    Executes when a reservation is created.

    The spec of a reservation is immutable so we do not need to listen for updates.
    """
    # If the reservation is Ready or Failed, there is nothing more to do
    if instance.status.phase in {api.ReservationPhase.READY, api.ReservationPhase.FAILED}:
        return
    # Patch the reservation phase to acknowledge that we are aware of it
    if instance.status.phase == api.ReservationPhase.UNKNOWN:
        instance.status.phase = api.ReservationPhase.PENDING
        await save_instance_status(instance)
    # Ensure that the referenced secret exists
    secrets = await ekclient.api("v1").resource("secrets")
    try:
        secret = await secrets.fetch(
            instance.spec.credential_secret_name,
            namespace = namespace
        )
    except ApiError as exc:
        if exc.status_code == 404:
            secret = await create_credential_secret(instance, body)
        else:
            raise
    # Extract the public key from the secret and reserve a domain for it
    try:
        public_key_b64 = secret.data[instance.spec.credential_secret_public_key_name]
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
    instance.status.phase = api.ReservationPhase.READY
    instance.status.subdomain = response_data["subdomain"]
    instance.status.fqdn = response_data["fqdn"]
    instance.status.fingerprint = response_data["fingerprints"][0]
    await save_instance_status(instance)


@model_handler(api.Client, kopf.on.create)
@model_handler(api.Client, kopf.on.update, field = "spec")
@model_handler(api.Client, kopf.on.resume)
async def client_changed(instance, name, namespace, body, **kwargs):
    """
    Executes when a client is created or the spec of a client is updated.

    It also runs for each client when the operator is resumed and will update the
    client resources to match the new configuration.
    """
    # Patch the phase to acknowledge that we are aware of the resource
    if instance.status.phase == api.ClientPhase.UNKNOWN:
        instance.status.phase = api.ClientPhase.PENDING
        await save_instance_status(instance)
    # Make sure the specified service exists
    services = await ekclient.api("v1").resource("services")
    try:
        service = await services.fetch(
            instance.spec.upstream.service_name,
            namespace = namespace
        )
    except ApiError as exc:
        if exc.status_code == 404:
            raise kopf.TemporaryError("could not find specified service")
        else:
            raise
    # Make sure the specified reservation exists
    reservations = await ekresource_for_model(api.Reservation)
    try:
        reservation = await reservations.fetch(
            instance.spec.reservation_name,
            namespace = namespace
        )
    except ApiError as exc:
        if exc.status_code == 404:
            raise kopf.TemporaryError("could not find specified reservation")
        else:
            raise
    else:
        reservation = api.Reservation.model_validate(reservation)
    # Wait for the specified reservation to become ready
    if reservation.status.phase != api.ReservationPhase.READY:
        # This condition normally only takes a short time to resolve
        raise kopf.TemporaryError("specified reservation is not ready yet", delay = 5)
    # Once the reservation is ready, update the status to reflect that
    if instance.status.phase == api.ClientPhase.PENDING:
        instance.status.phase = api.ClientPhase.RESERVATION_READY
        await save_instance_status(instance)
    # Get the credential associated with the reservation
    secrets = await ekclient.api("v1").resource("secrets")
    try:
        credential = await secrets.fetch(
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
    if instance.spec.upstream.port:
        # If an integer port is given, use it as-is
        # If the port is given but is not an integer, treat it as a port name
        try:
            upstream_port = int(instance.spec.upstream.port)
        except ValueError:
            try:
                upstream_port = next(
                    port["port"]
                    for port in service.spec.ports
                    if port["name"] == instance.spec.upstream.port
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
        client = instance
    )
    # Decide whether we need the service account and cluster role and delete if not
    service_account = default_loader.load("client/serviceaccount.yaml", **params)
    kopf.adopt(service_account, body)
    cluster_role_binding = default_loader.load("client/clusterrolebinding.yaml", **params)
    if (
        instance.spec.mitm_proxy.enabled and
        instance.spec.mitm_proxy.auth_inject.type == api.MITMProxyAuthInjectType.SERVICE_ACCOUNT
    ):
        await ekclient.apply_object(service_account, force = True)
        await ekclient.apply_object(cluster_role_binding, force = True)
    else:
        await ekclient.delete_object(cluster_role_binding)
        await ekclient.delete_object(service_account)
    # Always render the secret and deployment
    secret = default_loader.load("client/secret.yaml", **params)
    kopf.adopt(secret, body)
    await ekclient.apply_object(secret, force = True)
    # Take a checksum of the secret data to pass to the deployment, so that it rolls over
    hash = hashlib.sha256()
    for key in sorted(secret["stringData"].keys()):
        hash.update(secret["stringData"][key].encode())
    # when the config changes
    deployment = default_loader.load(
        "client/deployment.yaml",
        **params,
        config_checksum = hash.hexdigest()
    )
    kopf.adopt(deployment, body)
    await ekclient.apply_object(deployment, force = True)


@model_handler(api.Client, kopf.on.delete)
async def client_deleted(name, namespace, **kwargs):
    """
    Executes when a client is deleted.
    """
    # Kubernetes does not allow cluster-scoped objects to be owned by namespace-scoped ones
    # So we have to manually clean up the clusterrolebinding object if it exists
    name = f"zenith-client:{namespace}:{name}"
    rbac = ekclient.api("rbac.authorization.k8s.io/v1")
    clusterrolebindings = await rbac.resource("clusterrolebindings")
    await clusterrolebindings.delete(name)


@kopf.on.event(
    "apps",
    "deployments",
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
    client_status = await ekresource_for_model(api.Client, "status")
    try:
        _ = await client_status.patch(
            labels[f"{settings.api_group}/client"],
            { "status": { "phase": phase } },
            namespace = namespace
        )
    except ApiError as exc:
        if exc.status_code != 404:
            raise
