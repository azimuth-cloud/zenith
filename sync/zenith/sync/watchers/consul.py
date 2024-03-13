import asyncio
import logging
import math
import random
import uuid

import httpx

from ..config import SyncConfig, ConsulConfig
from ..model import Endpoint, Service, EventKind, Event

from . import base


class ServiceWatcher(base.ServiceWatcher):
    """
    Allows clients to watch changes to the set of services in Consul.
    """
    def __init__(self, config: ConsulConfig):
        self.config = config
        self._services = {}
        self._queues = {}
        self._running = False
        self._logger = logging.getLogger(__name__)

    async def _config(self, client, instance):
        """
        Fetches the configuration from Consul for the given instance.
        """
        service_id = instance["Service"]["ID"]
        url = f"/v1/kv/{self.config.config_key_prefix}/{service_id}?raw=true"
        response = await client.get(url)
        if 200 <= response.status_code < 300:
            self._logger.info("Found config for service instance %s", service_id)
            return response.json()
        elif response.status_code == 404:
            self._logger.info("No config for service instance %s", service_id)
            # Not found is fine - just return an empty configuration
            return {}
        else:
            self._logger.error("Error fetching config for service instance %s", service_id)
            response.raise_for_status()

    async def _wait(self, client, path, index = 0):
        """
        Fetches the path using a blocking query using the given index and returns a
        (result, next index) tuple.
        """
        while True:
            self._logger.info("Starting blocking query for %s", path)
            try:
                response = await client.get(
                    path,
                    params = {
                        "index": index,
                        "wait": f"{self.config.blocking_query_timeout}s",
                    },
                    # Consul adds a jitter of up to wait / 16
                    # So we wait one second longer than that so that most requests succeed
                    timeout = (
                        self.config.blocking_query_timeout +
                        math.ceil(self.config.blocking_query_timeout / 16) +
                        1
                    )
                )
            except httpx.ReadTimeout:
                self._logger.info("Blocking query timed out for %s - restarting", path)
                # On a read timeout, reset the index and try again
                index = 0
            else:
                if 200 <= response.status_code < 300:
                    next_index = int(response.headers['X-Consul-Index'])
                    self._logger.info(
                        "Blocking query successful for %s (index %d)",
                        path,
                        next_index
                    )
                    # Exit if the index has changed, otherwise go round again
                    if next_index != index:
                        # If the index goes backwards, reset it to zero
                        # The index must also be greater than zero
                        next_index = max(next_index if next_index >= index else 0, 0)
                        # Return the result tuple
                        return (response.json(), next_index)
                else:
                    self._logger.error("Blocking query failed for %s", path)
                    response.raise_for_status()
            # Wait for the specified amount of time before retrying
            # We add jitter of up to 1s either side of the wait time to spread out requests
            await asyncio.sleep(self.config.query_interval - 1 + random.uniform(0, 2))

    async def _wait_services(self, client, index = 0):
        """
        Waits for the list of services to change using a blocking query at the given index
        and returns a set of service names that match the given tag.
        """
        self._logger.info("Watching for changes to service list")
        services, next_idx = await self._wait(client, "/v1/catalog/services", index)
        return (
            {
                name
                for name, tags in services.items()
                if self.config.service_tag in tags
            },
            next_idx
        )

    async def _wait_service(self, client, name, index = 0):
        """
        Waits for the specified service to change using a blocking query at the given
        index and returns a service instance.
        """
        self._logger.info("Watching for changes to %s", name)
        # The return value from the health endpoint for the service is a list of instances
        instances, next_idx = await self._wait(client, f"/v1/health/service/{name}", index)
        # Request the configurations for each instance in parallel
        configs = await asyncio.gather(*[self._config(client, i) for i in instances])
        service = Service(
            name = name,
            # Get the address and port of each instance for which all the checks are passing
            endpoints = [
                Endpoint(
                    address = instance["Service"]["Address"],
                    port = instance["Service"]["Port"]
                )
                for instance in instances
                # Allow instances in the warning state as a grace period for health checks
                if all(c["Status"] in {"passing", "warning"} for c in instance["Checks"])
            ],
            # Merge the configurations associated with each instance
            config = { k: v for config in configs for k, v in config.items() }
        )
        return service, next_idx

    def _emit(self, kind, service):
        """
        Emit the given event on all queues.
        """
        event = Event(kind = kind, service = service)
        for queue in self._queues.values():
            queue.put_nowait(event)

    async def subscribe(self):
        """
        Subscribe to changes to the set of services.

        Returns a tuple of (current services, queue of events, unsubscribe function).
        """
        # Wait for the watcher to be running before subscribing
        while not self._running:
            await asyncio.sleep(0)  # Just yield control without actually waiting
        # Generate an id for the watch that is used to identify the queue
        watch_id = uuid.uuid4()
        # Attach the queue
        queue = self._queues[watch_id] = asyncio.Queue()
        # Freeze the current state as the initial state for the subscriber
        services = tuple(self._services.values())
        # The unsubscribe function just detachs the queue
        def unsubscribe():
            self._queues.pop(watch_id, None)
        return (services, queue, unsubscribe)

    async def _step(self, client, services_task, service_tasks):
        """
        Executes one step of the iteration, 
        """
        self._logger.info("Waiting for next task to complete")
        # Wait for the first task to complete
        tasks = set([services_task]).union(service_tasks.values())
        done, _ = await asyncio.wait(tasks, return_when = asyncio.FIRST_COMPLETED)
        self._logger.info("Processing %d completed tasks", len(done))
        for completed_task in done:
            if completed_task == services_task:
                self._logger.info("Service list query task completed")
                # Process any new or removed services if the list changed
                names, idx = completed_task.result()
                known_names = set(self._services.keys())
                for name in names.difference(known_names):
                    self._logger.info("Emitting created event for %s", name)
                    service, service_idx = await self._wait_service(client, name)
                    self._services[name] = service
                    self._emit(EventKind.CREATED, service)
                    service_tasks[name] = asyncio.create_task(
                        self._wait_service(client, name, service_idx)
                    )
                for name in known_names.difference(names):
                    self._logger.info("Emitting deleted event for %s", name)
                    self._services.pop(name)
                    self._emit(EventKind.DELETED, Service(name = name))
                    service_tasks.pop(name).cancel()
                services_task = asyncio.create_task(self._wait_services(client, idx))
            else:
                self._logger.info("Service query task completed")
                # If the completed task was a service health task, process the update
                service, service_idx = completed_task.result()
                self._logger.info("Service query task completed for %s", service.name)
                # We should only handle updates for services we know about
                if service.name in self._services:
                    self._logger.info("Emitting updated event for %s", service.name)
                    self._services[service.name] = service
                    self._emit(EventKind.UPDATED, service)
                    service_tasks[service.name] = asyncio.create_task(
                        self._wait_service(client, service.name, service_idx)
                    )
        # Return the tasks for the next iteration
        return services_task, service_tasks

    async def run(self):
        """
        Starts the watcher and runs until cancelled.
        """
        async with httpx.AsyncClient(base_url = self.config.url) as client:
            self._logger.info(
                "Initialised Consul client [url: %s, service_tag: %s]",
                self.config.url,
                self.config.service_tag
            )
            # First, we need to build the initial state
            names, idx = await self._wait_services(client)
            tasks = [self._wait_service(client, name) for name in names]
            initial_services = await asyncio.gather(*tasks)
            self._services = { service.name: service for service, _ in initial_services }
            # Now we have set up the initial state, mark ourselves as running
            self._running = True
            # Set up the inital tasks
            services_task = asyncio.create_task(self._wait_services(client, idx))
            service_tasks = {
                service.name: asyncio.create_task(
                    self._wait_service(client, service.name, service_idx)
                )
                for service, service_idx in initial_services
            }
            while True:
                services_task, service_tasks = await self._step(
                    client,
                    services_task,
                    service_tasks
                )

    @classmethod
    def from_config(cls, config_obj: SyncConfig) -> "ServiceWatcher":
        """
        Initialises an instance of the watcher from a config object.
        """
        return cls(config_obj.consul)
