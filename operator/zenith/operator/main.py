import base64
import dataclasses

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_ssh_public_key,
    load_ssh_private_key
)

import httpx

import kopf

from easykube import (
    Configuration,
    ApiError,
    ResourceSpec,
    resources as k8s
)

from .config import settings
from .models import v1alpha1 as api
from .template import default_loader


# Create an easykube client from the environment
from pydantic.json import pydantic_encoder
ekclient = Configuration.from_environment(json_encoder = pydantic_encoder).async_client()


# Load the CRDs and create easykube resource specs for them
reservation_crd = default_loader.load("crds/reservations.yaml")
Reservation = ResourceSpec.from_crd(reservation_crd)
ReservationStatus = dataclasses.replace(Reservation, name = f"{Reservation.name}/status")


@kopf.on.startup()
async def on_startup(**kwargs):
    """
    Runs on operator startup.
    """
    kopf_settings = kwargs["settings"]
    kopf_settings.persistence.finalizer = f"{settings.annotation_prefix}/finalizer"
    kopf_settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(
        prefix = settings.annotation_prefix
    )
    kopf_settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(
        prefix = settings.annotation_prefix,
        key = "last-handled-configuration",
    )
    kopf_settings.admission.server = kopf.WebhookServer(
        addr = "0.0.0.0",
        port = settings.webhook.port,
        host = settings.webhook.host,
        certfile = settings.webhook.certfile,
        pkeyfile = settings.webhook.keyfile
    )
    if settings.webhook.managed:
        kopf_settings.admission.managed = f"webhook.{settings.api_group}"
    # Create the CRDs
    await ekclient.apply_object(reservation_crd)


@kopf.on.cleanup()
async def on_cleanup(**kwargs):
    """
    Runs on operator shutdown.
    """
    await ekclient.aclose()


@kopf.on.validate(k8s.Secret.api_version, k8s.Secret.name, id = "validate-credential")
async def validate_credential(body, operation, **kwargs):
    """
    Validates secrets that have the Zenith credential type.
    """
    if body["type"] != settings.credential_secret_type:
        return
    if operation not in {"CREATE", "UPDATE"}:
        return
    data = body.get("data", {})
    if "ssh-publickey" not in data:
        raise kopf.AdmissionError("required key ssh-publickey not present")
    if "ssh-privatekey" not in data:
        raise kopf.AdmissionError("required key ssh-privatekey not present")
    try:
        _ = load_ssh_public_key(base64.b64decode(data["ssh-publickey"]))
    except (ValueError, UnsupportedAlgorithm):
        raise kopf.AdmissionError("ssh-publickey is not a valid SSH public key")
    try:
        _ = load_ssh_private_key(base64.b64decode(data["ssh-privatekey"]), password = None)
    except (ValueError, UnsupportedAlgorithm):
        raise kopf.AdmissionError("ssh-privatekey is not a valid password-less SSH private key")


@kopf.on.validate(Reservation.api_version, Reservation.name, id = "validate-reservation")
async def validate_reservation(body, namespace, operation, **kwargs):
    """
    Validates Zenith reservations.
    """
    if operation not in {"CREATE", "UPDATE"}:
        return
    # If a secret name is given and the secret exists, it must have the Zenith credential type
    reservation = api.Reservation.parse_obj(body)
    if not reservation.spec.ssh_keypair_secret_name:
        return
    try:
        secret = await k8s.Secret(ekclient).fetch(
            reservation.spec.ssh_keypair_secret_name,
            namespace = namespace
        )
    except ApiError as exc:
        if exc.status_code != 404:
            raise
    else:
        if secret.type != settings.credential_secret_type:
            raise kopf.AdmissionError(
                f"referenced secret must be of type '{settings.credential_secret_type}'"
            )


async def create_ssh_keypair_secret(name, namespace, reservation):
    """
    Creates a secret containing an SSH keypair with the given reservation as the owner.
    """
    private_key = Ed25519PrivateKey.generate()
    secret_data = {
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "zenith-operator",
                "zenith.stackhpc.com/reservation": reservation.metadata.name,
            },
        },
        "type": settings.credential_secret_type,
        "stringData": {
            "ssh-privatekey": (
                private_key
                    .private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
                    .decode()
            ),
            "ssh-publickey": (
                private_key
                    .public_key()
                    .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
                    .decode()
            ),
        },
    }
    kopf.adopt(secret_data, reservation)
    return await k8s.Secret(ekclient).create(secret_data, namespace = namespace)


@kopf.on.create(Reservation.api_version, Reservation.name)
@kopf.on.update(Reservation.api_version, Reservation.name, field = "spec")
async def on_reservation_changed(name, namespace, body, **kwargs):
    """
    Executes when the spec of a reservation is changed.
    """
    reservation = api.Reservation.parse_obj(body)
    # If the reservation is Ready or Failed, there is nothing more to do
    if reservation.status.phase in {api.ReservationPhase.READY, api.ReservationPhase.FAILED}:
        return
    # Patch the reservation phase to acknowledge that we are aware of it
    if reservation.status.phase == api.ReservationPhase.UNKNOWN:
        _ = await ReservationStatus(ekclient).patch(
            name,
            {
                "status": {
                    "phase": api.ReservationPhase.PENDING,
                },
            },
            namespace = namespace
        )
    # If there is no secret name, derive one from the reservation name and patch the spec
    # Note that patching the spec will cause this handler to run again, so that is all we do
    if not reservation.spec.ssh_keypair_secret_name:
        _ = await Reservation(ekclient).patch(
            name,
            {
                "spec": {
                    "sshKeypairSecretName": f"{name}-credential"
                }
            },
            namespace = namespace
        )
        return
    # Ensure that the referenced secret exists
    try:
        secret = await k8s.Secret(ekclient).fetch(
            reservation.spec.ssh_keypair_secret_name,
            namespace = namespace
        )
    except ApiError as exc:
        if exc.status_code != 404:
            raise
        secret = await create_ssh_keypair_secret(
            reservation.spec.ssh_keypair_secret_name,
            namespace,
            body
        )
    # Extract the public key from the secret and reserve a domain for it
    public_key = base64.b64decode(secret.data["ssh-publickey"]).decode()
    async with httpx.AsyncClient(base_url = settings.registrar_admin_url) as zclient:
        response = await zclient.post(
            "/admin/reserve",
            json = {
                "public_keys": [public_key],
            }
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
        { "status": status.dict(by_alias = True) },
        namespace = namespace
    )
