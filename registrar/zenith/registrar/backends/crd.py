import base64
import logging
import typing

from easykube import Configuration, ApiError

from .. import config

from . import base


def fingerprint_urlsafe(fingerprint: bytes) -> str:
    return base64.urlsafe_b64encode(fingerprint).decode().rstrip("=")


def fingerprint_str(fingerprint: bytes) -> str:
    return base64.b64encode(fingerprint).decode().rstrip("=")


class Backend(base.Backend):
    """
    Backend that stores services using a Kubernetes CRD.
    """
    def __init__(self,
        api_version: str,
        target_namespace: str,
        fingerprint_label: str
    ):
        self.logger = logging.getLogger(__name__)
        # Initialise an easykube client from the environment
        self.ekclient = Configuration.from_environment().async_client(
            default_namespace = target_namespace
        )
        self.api_version = api_version
        self.fingerprint_label = fingerprint_label

    async def startup(self):
        """
        Perform any startup tasks that are required.
        """
        await self.ekclient.__aenter__()

    async def shutdown(self):
        """
        Perform any shutdown tasks that are required.
        """
        await self.ekclient.__aexit__(None, None, None)

    async def reserve_subdomain(self, subdomain: str):
        # Create the service record
        # If we are the one that gets to do the create, we win any races
        ekservices = await self.ekclient.api(self.api_version).resource("services")
        try:
            service = await ekservices.create({ "metadata": { "name": subdomain } })
        except ApiError as exc:
            if exc.status_code == 409:
                raise base.SubdomainAlreadyReserved(subdomain)
            else:
                raise
        # Also create an empty endpoints resource that is owned by the service
        ekendpoints = await self.ekclient.api(self.api_version).resource("endpoints")
        _ = await ekendpoints.create_or_replace(
            subdomain,
            {
                "metadata": {
                    "name": service["metadata"]["name"],
                    "namespace": service["metadata"]["namespace"],
                    "ownerReferences": [
                        {
                            "apiVersion": service["apiVersion"],
                            "kind": service["kind"],
                            "name": service["metadata"]["name"],
                            "uid": service["metadata"]["uid"],
                            "blockOwnerDeletion": True,
                        },
                    ],
                }
            }
        )

    async def init_subdomain(self, subdomain: str, fingerprint: bytes):
        # Fetch the existing service record for the subdomain
        ekresource = await self.ekclient.api(self.api_version).resource("services")
        try:
            service = await ekresource.fetch(subdomain)
        except ApiError as exc:
            if exc.status_code == 404:
                raise base.SubdomainNotReserved(subdomain)
            else:
                raise
        # If the service already has a public key, we are done
        if service.get("spec", {}).get("publicKeyFingerprint"):
            raise base.SubdomainAlreadyInitialised(subdomain)
        # Modify the resource and replace it
        # Using replace with a resource version that we know does not have a public key
        # should ensure we are the first operation to set a public key
        # Set a label that allows us to search by fingerprint later
        # The label uses a URL-safe version of the fingerprint because of the allowed chars
        labels = service["metadata"].setdefault("labels", {})
        labels[self.fingerprint_label] = fingerprint_urlsafe(fingerprint)
        spec = service.setdefault("spec", {})
        spec["publicKeyFingerprint"] = fingerprint_str(fingerprint)
        try:
            _ = await self.ekclient.replace_object(service)
        except ApiError as exc:
            if exc.status_code == 409:
                raise base.SubdomainAlreadyInitialised(subdomain)
            else:
                raise

    async def subdomain_for_public_key(self, fingerprint: bytes) -> str:
        # Fetch the first subdomain record that has the fingerprint as a label
        ekresource = await self.ekclient.api(self.api_version).resource("services")
        labels = { self.fingerprint_label: fingerprint_urlsafe(fingerprint) }
        service = await ekresource.first(labels = labels)
        if service:
            return service.metadata.name
        else:
            raise base.PublicKeyNotAssociated(fingerprint)

    @classmethod
    def from_config(cls, config_obj: config.RegistrarConfig) -> "Backend":
        """
        Initialises an instance of the backend from a config object.
        """
        return cls(
            config_obj.crd_api_version,
            config_obj.crd_target_namespace,
            config_obj.crd_fingerprint_label
        )
