import logging
import typing

from easykube import Configuration, ApiError
from kube_custom_resource import CustomResourceRegistry

from ... import config, model

from .. import base

from . import models


class Store(base.Store):
    """
    Store implementation that provides access to services stored in Consul.
    """
    def __init__(self, config_obj: config.KubernetesConfig):
        self.logger = logging.getLogger(__name__)
        self.config = config_obj
        # Initialise the custom resource registry
        self.registry = CustomResourceRegistry(
            self.config.crd_api_group,
            self.config.crd_categories
        )
        # Initialise an easykube client from the environment
        self.ekclient = Configuration.from_environment().async_client(
            default_field_manager = self.config.easykube_field_manager,
            default_namespace = self.config.target_namespace
        )

    async def startup(self):
        """
        Perform any startup tasks that are required.
        """
        await self.ekclient.__aenter__()
        # Register the CRDs
        self.registry.discover_models(models)
        for crd in self.registry:
            await self.ekclient.apply_object(crd.kubernetes_resource(), force = True)

    async def shutdown(self):
        """
        Perform any shutdown tasks that are required.
        """
        await self.ekclient.__aexit__(None, None, None)

    async def _ekresource_for_model(self, model, subresource = None):
        """
        Returns an easykube resource for the specified model.
        """
        api = self.ekclient.api(f"{self.config.crd_api_group}/{model._meta.version}")
        resource = model._meta.plural_name
        if subresource:
            resource = f"{resource}/{subresource}"
        return await api.resource(resource)

    async def _service_for_endpoints(self, endpoints):
        """
        Produces a service DTO instance for the given endpoints resource.
        """

    async def _produce_events(self, ep_events):
        """
        Yield event DTOs for each endpoints event.
        """
        async for event in ep_events:
            print(event)
            if False:
                yield

    async def watch(self) -> typing.Tuple[
        typing.Iterable[model.Service],
        typing.AsyncIterable[model.Event]
    ]:
        ekresource = await self._ekresource_for_model(models.v1alpha1.Endpoints)
        initial_eps, ep_events = await ekresource.watch_list()
        # Produce the initial services
        initial_services = []
        for ep in initial_eps:
            initial_services.append(await self._service_for_endpoints(ep))
        return [], self._produce_events(ep_events)

    @classmethod
    def from_config(cls, config_obj: config.SyncConfig) -> "Store":
        return cls(config_obj.kubernetes)
