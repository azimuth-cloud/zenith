import asyncio
import datetime
import logging
import typing

from easykube import ApiError, Configuration
from kube_custom_resource import CustomResource, CustomResourceRegistry

from ... import config, metrics, model  # noqa: TID252
from .. import base  # noqa: TID252
from . import models as crds
from .models import v1alpha1 as api


class StoreMetric(metrics.Metric):
    prefix = "zenith_service"

    def labels(self, obj):
        return {
            "service_namespace": obj.metadata.namespace,
            "service_name": obj.metadata.name,
        }


class ServiceInfo(StoreMetric):
    suffix = "info"
    description = "Information about Zenith services"

    def labels(self, obj):
        return {
            **super().labels(obj),
            "created_at": obj.metadata["creationTimestamp"],
            "fingerprint": obj.get("spec", {}).get("publicKeyFingerprint", ""),
        }


class ServiceEndpointInfo(StoreMetric):
    suffix = "endpoint_info"
    description = "Information about the endpoints for Zenith services"

    def samples(self):
        for obj in self._objs:
            labels = super().labels(obj)
            for name, endpoint in obj.get("spec", {}).get("endpoints", {}).items():
                endpoint_labels = {
                    **labels,
                    "endpoint_id": name,
                    "endpoint_address": endpoint["address"],
                    "endpoint_port": endpoint["port"],
                    "endpoint_status": endpoint["status"],
                }
                yield endpoint_labels, 1


class Store(base.Store):
    """
    Store implementation that provides access to services stored in Consul.
    """

    def __init__(self, config_obj: config.KubernetesConfig):
        self.logger = logging.getLogger(__name__)
        self.config = config_obj
        # Initialise the custom resource registry
        self.registry = CustomResourceRegistry(
            self.config.crd_api_group, self.config.crd_categories
        )
        # Initialise an easykube client from the environment
        self.ekclient = Configuration.from_environment().async_client(
            default_field_manager=self.config.easykube_field_manager,
            default_namespace=self.config.target_namespace,
        )

    async def startup(self):
        """
        Perform any startup tasks that are required.
        """
        await self.ekclient.__aenter__()
        # Register the CRDs
        self.registry.discover_models(crds)
        for crd in self.registry:
            await self.ekclient.apply_object(crd.kubernetes_resource(), force=True)

    async def shutdown(self):
        """
        Perform any shutdown tasks that are required.
        """
        await self.ekclient.__aexit__(None, None, None)

    async def _ekresource_for_model(self, model, subresource=None):
        """
        Returns an easykube resource for the specified model.
        """
        api = self.ekclient.api(f"{self.config.crd_api_group}/{model._meta.version}")
        resource = model._meta.plural_name
        if subresource:
            resource = f"{resource}/{subresource}"
        return await api.resource(resource)

    def _service_for_endpoints(self, endpoints):
        """
        Produces a service DTO instance for the given endpoints resource.
        """
        # Parse the endpoint into a model instance
        endpoints = api.Endpoints.model_validate(endpoints)
        return model.Service(
            name=endpoints.metadata.name,
            endpoints=[
                model.Endpoint(id=id, address=ep.address, port=ep.port)
                for id, ep in endpoints.spec.endpoints.items()  # noqa: A001
                if ep.status != api.EndpointStatus.CRITICAL
            ],
            # Merge the configs associated with each endpoint
            config={
                k: v
                for ep in endpoints.spec.endpoints.values()
                for k, v in ep.config.items()
            },
        )

    async def _produce_events(self, ep_events):
        """
        Yield event DTOs for each endpoints event.
        """
        async for event in ep_events:
            if event["type"] == "ADDED":
                event_type = model.EventKind.CREATED
            elif event["type"] == "MODIFIED":
                event_type = model.EventKind.UPDATED
            elif event["type"] == "DELETED":
                event_type = model.EventKind.DELETED
            else:
                continue
            yield model.Event(event_type, self._service_for_endpoints(event["object"]))

    async def watch(
        self,
    ) -> tuple[typing.Iterable[model.Service], typing.AsyncIterable[model.Event]]:
        ekresource = await self._ekresource_for_model(api.Endpoints)
        initial_eps, ep_events = await ekresource.watch_list()
        return (
            [self._service_for_endpoints(ep) for ep in initial_eps],
            self._produce_events(ep_events),
        )

    async def run(self):
        # We need to move dead endpoints into the critical state, and reap old ones
        # To determine which endpoints to reap, we check the leases
        ekleases = await self._ekresource_for_model(api.Lease)
        ekendpoints = await self._ekresource_for_model(api.Endpoints)
        while True:
            now = datetime.datetime.now(tz=datetime.timezone.utc)
            async for lease in ekleases.list():
                lease = api.Lease.model_validate(lease)
                # Split the lease name into the subdomain and ID
                subdomain, id = lease.metadata.name.split("-", maxsplit=1)  # noqa: A001
                # Check if the lease has expired or needs reaping
                reap_after_delta = datetime.timedelta(seconds=lease.spec.reap_after)
                ttl_delta = datetime.timedelta(seconds=lease.spec.ttl)
                # If the lease has gone past it's reap delta, remove it and the endpoint
                if lease.spec.renewed_at + reap_after_delta < now:
                    try:
                        await ekendpoints.json_patch(
                            subdomain,
                            [
                                {
                                    "op": "remove",
                                    "path": f"/spec/endpoints/{id}",
                                },
                            ],
                        )
                    except ApiError as exc:
                        # If the endpoint is already gone, which is fine,
                        # we will get a 422
                        if exc.status_code != 422:
                            raise
                    await ekleases.delete(lease.metadata.name)
                # If the lease has gone past it's TTL, mark the endpoint as critical
                elif lease.spec.renewed_at + ttl_delta < now:
                    try:
                        await ekendpoints.json_patch(
                            subdomain,
                            [
                                {
                                    "op": "replace",
                                    "path": f"/spec/endpoints/{id}/status",
                                    "value": api.EndpointStatus.CRITICAL.value,
                                },
                            ],
                        )
                    except ApiError as exc:
                        # If the endpoint is not present, which is fine,
                        # we will get a 422
                        if exc.status_code != 422:
                            raise
            # Wait for the configured duration
            await asyncio.sleep(self.config.crd_endpoint_check_interval)

    async def _populate_metric(
        self, metric: metrics.Metric, model: type[CustomResource]
    ) -> metrics.Metric:
        """
        Adds instances of the specified model to the given metric.
        """
        ekresource = await self._ekresource_for_model(model)
        async for instance in ekresource.list():
            metric.add_obj(instance)
        return metric

    async def metrics(self) -> typing.Iterable[metrics.Metric]:
        return await asyncio.gather(
            self._populate_metric(ServiceInfo(), api.Service),
            self._populate_metric(ServiceEndpointInfo(), api.Endpoints),
        )

    @classmethod
    def from_config(cls, config_obj: config.SyncConfig) -> "Store":
        return cls(config_obj.kubernetes)
