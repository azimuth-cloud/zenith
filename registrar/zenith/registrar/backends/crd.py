import logging
import typing

from easykube import Configuration, ApiError

from .. import config

from . import base


class Backend(base.Backend):
    """
    Backend that stores services using a Kubernetes CRD.
    """
    def __init__(self, api_version: str, target_namespace: str):
        self.logger = logging.getLogger(__name__)
        # Initialise an easykube client from the environment
        self.ekclient = Configuration.from_environment().async_client(
            default_namespace = target_namespace
        )
        self.api_version = api_version

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

    async def _ekresource(self):
        """
        Returns an easykube resource for manipulating services.
        """
        return await self.ekclient.api(self.api_version).resource("services")

    async def reserve_subdomain(self, subdomain: str):
        # Create the service record
        # If we are the one that gets to do the create, we win any races
        ekresource = await self._ekresource()
        try:
            _ = await ekresource.create({ "metadata": { "name": subdomain } })
        except ApiError as exc:
            if exc.status_code == 409:
                raise base.SubdomainAlreadyReserved(subdomain)
            else:
                raise

    @classmethod
    def from_config(cls, config_obj: config.RegistrarConfig) -> "Backend":
        """
        Initialises an instance of the backend from a config object.
        """
        return cls(config_obj.crd_api_version, config_obj.crd_target_namespace)
