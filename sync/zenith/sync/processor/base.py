import asyncio
import random
import typing

from .. import config, model, store


class RetryRequired(Exception):
    """
    Raised to explicitly request a retry with a warning message.
    """


class Processor:
    """
    Processes service events.
    """
    def __init__(self, logger, retry_max_backoff: int):
        self.logger = logger
        self.retry_max_backoff = retry_max_backoff

    async def known_services(self) -> typing.Set[str]:
        """
        Return a set of known services for the processor.
        """
        raise NotImplementedError

    async def service_updated(self, service: model.Service):
        """
        Called when a service is updated and should reconcile as required.
        """
        raise NotImplementedError

    async def service_removed(self, service: model.Service):
        """
        Called when a service is removed and should reconcile as required.
        """
        raise NotImplementedError

    async def process_event(self, event: model.Event):
        """
        Processes an event with retries.
        """
        # We handle an event by calling separate updated/deleted methods
        retries = 0
        while True:
            try:
                # When a service has no active endpoints, we want to remove it
                if event.kind == model.EventKind.DELETED or not event.service.endpoints:
                    await self.service_removed(event.service)
                else:
                    await self.service_updated(event.service)
            except asyncio.CancelledError:
                self.logger.info(
                    "Processing of %s event for %s was cancelled",
                    event.kind.name,
                    event.service.name
                )
                # Propagate the cancelled event
                raise
            except RetryRequired as exc:
                # If a retry is explicitly requested, just issue a warning
                self.logger.warning(
                    "Retry required for %s event for %s - %s",
                    event.kind.name,
                    event.service.name,
                    str(exc)
                )
            except Exception:
                self.logger.exception(
                    "Error processing %s event for %s",
                    event.kind.name,
                    event.service.name
                )
            else:
                self.logger.info(
                    "Processed %s event for %s successfully",
                    event.kind.name,
                    event.service.name
                )
                # We are done, so break out of the loop
                break
            # Retry the processing of the event after an exponential backoff
            backoff = 2**retries + random.uniform(0, 1)
            clamped_backoff = min(backoff, self.retry_max_backoff)
            await asyncio.sleep(clamped_backoff)
            retries = retries + 1

    async def schedule_task(
        self,
        tasks: typing.Dict[str, asyncio.Task],
        event: model.Event
    ) -> typing.Dict[str, asyncio.Task]:
        """
        Schedules a task to process the specified event and returns the new set of tasks.

        If an existing task exists for the service, it is cancelled first.
        """
        existing_task = tasks.pop(event.service.name, None)
        if existing_task and not existing_task.done():
            self.logger.info("Cancelling existing task for %s", event.service.name)
            existing_task.cancel()
            # Wait for the task to actually finish cancelling
            try:
                await asyncio.wait_for(existing_task, 10)
            except asyncio.CancelledError:
                pass
        self.logger.info(
            "Scheduling task to process %s event for %s",
            event.kind.name,
            event.service.name
        )
        tasks[event.service.name] = asyncio.create_task(self.process_event(event))
        return tasks

    async def run(self, store: store.Store):
        """
        Run the processor against services and events from the given store.
        """
        # Map of service names to the active processing task for that service
        tasks: typing.Dict[str, asyncio.Task] = {}
        # Begin watching the store
        initial_services, events = await store.watch()
        # Process the initial services vs the known services
        known_services = await self.known_services()
        for service in initial_services:
            event = model.Event(model.EventKind.UPDATED, service)
            tasks = await self.schedule_task(tasks, event)
        for name in known_services.difference(s.name for s in initial_services):
            event = model.Event(model.EventKind.DELETED, model.Service(name))
            tasks = await self.schedule_task(tasks, event)
        # Schedule a processing task for each incoming event
        async for event in events:
            # Before scheduling a new task, reap any completed tasks
            tasks = { name: task for name, task in tasks.items() if not task.done() }
            tasks = await self.schedule_task(tasks, event)

    async def startup(self):
        """
        Perform any startup tasks that are required.
        """

    async def shutdown(self):
        """
        Perform any shutdown tasks that are required.
        """

    async def __aenter__(self):
        await self.startup()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.shutdown()

    @classmethod
    def from_config(cls, config_obj: config.SyncConfig) -> "Processor":
        """
        Initialises an instance of the processor from a config object.
        """
        raise NotImplementedError
