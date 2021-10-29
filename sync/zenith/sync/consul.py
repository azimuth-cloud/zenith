import asyncio
import logging
import uuid

import httpx

from .model import Endpoint, Service, EventKind, Event


logger = logging.getLogger(__name__)


class ServiceWatcher:
    """
    Allows clients to watch changes to the set of services in Consul.
    """
    def __init__(self, config):
        self.config = config
        self._services = {}
        self._queues = {}
        self._running = False

    async def _tls_config(self, client, instance):
        """
        Fetches the TLS configuration from Consul for the given instance.
        """
        url = f"/v1/kv/{self.config.tls_key_prefix}/{instance['Service']['ID']}?raw=true"
        response = await client.get(url)
        if 200 <= response.status_code < 300:
            return response.json()
        elif response.status_code == 404:
            # Not found is fine - just return an empty configuration
            return {}
        response.raise_for_status()

    async def _wait(self, client, path, index = 0):
        """
        Fetches the path using a blocking query using the given index and returns a
        (result, next index) tuple.
        """
        params = { "index": index, "wait": f"{self.config.blocking_query_timeout}s" }
        while True:
            try:
                response = await client.get(
                    path,
                    params = params,
                    timeout = self.config.blocking_query_timeout + 1
                )
            except httpx.ReadTimeout:
                # Ignore read timeouts and just continue with the same index
                continue
            else:
                response.raise_for_status()
                next_index = int(response.headers['X-Consul-Index'])
                # If the index hasn't changed, do another iteration
                if next_index != index:
                    break
        # If the index goes backwards, reset it to zero
        # The index must also be greater than zero
        next_index = max(next_index if index is None or next_index >= index else 0, 0)
        # Return the result tuple
        return (response.json(), next_index)

    async def _wait_services(self, client, index = 0):
        """
        Waits for the list of services to change using a blocking query at the given index
        and returns a set of service names that match the given tag.
        """
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
        # The return value from the health endpoint for the service is a list of instances
        instances, next_idx = await self._wait(client, f"/v1/health/service/{name}", index)
        # Request the TLS configurations for each instance in parallel
        tls_configs = await asyncio.gather(*[self._tls_config(client, i) for i in instances])
        service = Service(
            name = name,
            # Merge the metadata from the instances together
            metadata = {
                k: v
                for instance in instances
                for k, v in (instance["Service"].get("Meta") or {}).items()
            },
            # Get the address and port of each instance for which all the checks are passing
            endpoints = [
                Endpoint(
                    address = instance["Service"]["Address"],
                    port = instance["Service"]["Port"]
                )
                for instance in instances
                if all(c["Status"] == "passing" for c in instance["Checks"])
            ],
            # Merge the TLS configuration associated with each instance
            tls = { k: v for tls_config in tls_configs for k, v in tls_config.items() }
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

        Returns a tuple of (current services, async iterator of events, unsubscribe function).
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
        # Simple async iterator that just yields events from our queue
        async def events():
            while True:
                yield (await queue.get())
        # The unsubscribe function just detachs the queue
        def unsubscribe():
            self._queues.pop(watch_id, None)
        return (services, events(), unsubscribe)

    async def _step(self, client, services_task, service_tasks):
        """
        Executes one step of the iteration, 
        """
        # Wait for the first task to complete
        done, _ = await asyncio.wait(
            set([services_task]).union(service_tasks.values()),
            return_when = asyncio.FIRST_COMPLETED
        )
        for completed_task in done:
            if completed_task == services_task:
                # Process any new or removed services if the list changed
                names, idx = completed_task.result()
                known_names = set(self._services.keys())
                for name in names.difference(known_names):
                    service, service_idx = await self._wait_service(client, name)
                    self._services[name] = service
                    self._emit(EventKind.CREATED, service)
                    service_tasks[name] = asyncio.create_task(
                        self._wait_service(client, name, service_idx)
                    )
                for name in known_names.difference(names):
                    self._services.pop(name)
                    self._emit(EventKind.DELETED, Service(name = name))
                    service_tasks.pop(name).cancel()
                services_task = asyncio.create_task(self._wait_services(client, idx))
            else:
                # If the completed task was a service health task, process the update
                service, service_idx = completed_task.result()
                # We should only handle updates for services we know about
                if service.name in self._services:
                    previous = self._services[service.name]
                    self._services[service.name] = service
                    # Only emit the event if the service (as we present it) has changed
                    # For instance, Consul will notify us when a new but unhealthy
                    # instance is added, but we don't care until it is healthy
                    if previous != service:
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
            logger.info(
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
