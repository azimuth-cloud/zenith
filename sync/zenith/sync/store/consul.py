import asyncio
import logging
import math
import random
import typing

import httpx

from .. import config, model, util

from . import base


class Store(base.Store):
    """
    Store implementation that provides access to services stored in Consul.
    """

    def __init__(self, config: config.ConsulConfig):
        self.config = config
        self.client = httpx.AsyncClient(base_url=self.config.url)
        self.logger = logging.getLogger(__name__)

    async def startup(self):
        """
        Perform any startup tasks that are required.
        """
        await self.client.__aenter__()

    async def shutdown(self):
        """
        Perform any shutdown tasks that are required.
        """
        await self.client.__aexit__(None, None, None)

    async def _config(self, instance):
        """
        Fetches the configuration from Consul for the given instance.
        """
        service_id = instance["Service"]["ID"]
        url = f"/v1/kv/{self.config.config_key_prefix}/{service_id}?raw=true"
        response = await self.client.get(url)
        if 200 <= response.status_code < 300:
            self.logger.info("Found config for service instance %s", service_id)
            return response.json()
        elif response.status_code == 404:
            self.logger.info("No config for service instance %s", service_id)
            # Not found is fine - just return an empty configuration
            return {}
        else:
            self.logger.error(
                "Error fetching config for service instance %s", service_id
            )
            response.raise_for_status()

    async def _wait(self, path, index=0):
        """
        Fetches the path using a blocking query using the given index and returns a
        (result, next index) tuple.
        """
        while True:
            self.logger.info("Starting blocking query for %s", path)
            try:
                response = await self.client.get(
                    path,
                    params={
                        "index": index,
                        "wait": f"{self.config.blocking_query_timeout}s",
                    },
                    # Consul adds a jitter of up to wait / 16
                    # So we wait one second longer than that so that most requests succeed
                    timeout=(
                        self.config.blocking_query_timeout
                        + math.ceil(self.config.blocking_query_timeout / 16)
                        + 1
                    ),
                )
            except httpx.ReadTimeout:
                self.logger.info("Blocking query timed out for %s - restarting", path)
                # On a read timeout, reset the index and try again
                index = 0
            else:
                if 200 <= response.status_code < 300:
                    next_index = int(response.headers["X-Consul-Index"])
                    self.logger.info(
                        "Blocking query successful for %s (index %d)", path, next_index
                    )
                    # Exit if the index has changed, otherwise go round again
                    if next_index != index:
                        # If the index goes backwards, reset it to zero
                        # The index must also be greater than zero
                        next_index = max(next_index if next_index >= index else 0, 0)
                        # Return the result tuple
                        return (response.json(), next_index)
                else:
                    self.logger.error("Blocking query failed for %s", path)
                    response.raise_for_status()
            # Wait for the specified amount of time before retrying
            # We add jitter of up to 1s either side of the wait time to spread out requests
            await asyncio.sleep(self.config.query_interval - 1 + random.uniform(0, 2))

    async def _wait_services(self, index=0):
        """
        Waits for the list of services to change using a blocking query at the given index
        and returns a set of service names that match the given tag.
        """
        self.logger.info("Watching for changes to service list")
        services, next_idx = await self._wait("/v1/catalog/services", index)
        return (
            {
                name
                for name, tags in services.items()
                if self.config.service_tag in tags
            },
            next_idx,
        )

    async def _wait_service(self, name, index=0):
        """
        Waits for the specified service to change using a blocking query at the given
        index and returns a service instance.
        """
        self.logger.info("Watching for changes to %s", name)
        # The return value from the health endpoint for the service is a list of instances
        instances, next_idx = await self._wait(f"/v1/health/service/{name}", index)
        # Request the configurations for each instance in parallel
        configs = await asyncio.gather(*[self._config(i) for i in instances])
        service = model.Service(
            name=name,
            # Get the address and port of each instance for which all the checks are passing
            endpoints=[
                model.Endpoint(
                    address=instance["Service"]["Address"],
                    port=instance["Service"]["Port"],
                )
                for instance in instances
                # Allow instances in the warning state as a grace period for health checks
                if all(
                    c["Status"] in {"passing", "warning"} for c in instance["Checks"]
                )
            ],
            # Merge the configurations associated with each instance
            config={k: v for config in configs for k, v in config.items()},
        )
        return service, next_idx

    async def _produce_events(self, list_idx, initial_services):
        """
        Yield events starting from the specified list index and initial services.
        """
        # Record the names that we know so that we can diff when a new list is available
        known_services = {service.name for service, _ in initial_services}
        # Set up the initial tasks
        services_task = asyncio.create_task(self._wait_services(list_idx))
        service_tasks = {
            service.name: asyncio.create_task(
                self._wait_service(service.name, service_idx)
            )
            for service, service_idx in initial_services
        }
        while True:
            self.logger.info("Waiting for next task to complete")
            # Wait for the first task to complete
            tasks = set([services_task]).union(service_tasks.values())
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            self.logger.info("Processing %d completed tasks", len(done))
            for completed_task in done:
                if completed_task == services_task:
                    self.logger.info("Service list query task completed")
                    # Process any new or removed services if the list changed
                    names, idx = completed_task.result()
                    for name in names.difference(known_services):
                        self.logger.info("Emitting created event for %s", name)
                        service, service_idx = await self._wait_service(name)
                        yield model.Event(model.EventKind.CREATED, service)
                        known_services.add(name)
                        service_tasks[name] = asyncio.create_task(
                            self._wait_service(name, service_idx)
                        )
                    for name in known_services.difference(names):
                        self.logger.info("Emitting deleted event for %s", name)
                        yield model.Event(
                            model.EventKind.DELETED, model.Service(name=name)
                        )
                        known_services.discard(name)
                        await util.task_cancel_and_wait(service_tasks.pop(name))
                    services_task = asyncio.create_task(self._wait_services(idx))
                else:
                    self.logger.info("Service query task completed")
                    # If the completed task was a service health task, process the update
                    service, service_idx = completed_task.result()
                    self.logger.info(
                        "Service query task completed for %s", service.name
                    )
                    # We should only handle updates for services we know about
                    if service.name in known_services:
                        self.logger.info("Emitting updated event for %s", service.name)
                        yield model.Event(model.EventKind.UPDATED, service)
                        service_tasks[service.name] = asyncio.create_task(
                            self._wait_service(service.name, service_idx)
                        )

    async def watch(
        self,
    ) -> typing.Tuple[
        typing.Iterable[model.Service], typing.AsyncIterable[model.Event]
    ]:
        """
        Watches Consul services until cancelled.
        """
        self.logger.info(
            "Watching Consul services [url: %s, service_tag: %s]",
            self.config.url,
            self.config.service_tag,
        )
        # First, we need to build the initial state
        names, idx = await self._wait_services()
        tasks = [self._wait_service(name) for name in names]
        initial_services = await asyncio.gather(*tasks)
        # Return the initial set of services and the events iterable
        return tuple(s for s, _ in initial_services), self._produce_events(
            idx, initial_services
        )

    @classmethod
    def from_config(cls, config_obj: config.SyncConfig) -> "Store":
        return cls(config_obj.consul)
