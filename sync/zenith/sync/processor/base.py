import asyncio
import collections
import random
import typing

from .. import config, metrics, model, store, util


class EventQueue:
    """
    Queue of (event, retries) tuples.

    The queue is "smart" in a few ways:

      1. It has explicit operations for enqueuing a new event and requeuing an event that has
         previously been attempted.

      2. Requeuing of an event that has been previously attempted only happens after a backoff.
         This happens asynchronously so that it does not block the worker from moving on to the
         next event.

      3. At most one event per service can be in the queue at any given time.
         New events trump any existing events, and existing events trump requeued events.

      4. Only one event per service is allowed to be "active" at any given time.
         The queue records when an event for a service leaves the queue, and does not allow any
         more events for that service to leave the queue until it has been notified that
         processing of that event has been completed (either explicitly or by requeuing).
    """

    def __init__(self, requeue_max_backoff: int):
        self.requeue_max_backoff = requeue_max_backoff
        # The main queue of events
        self._queue: typing.List[typing.Tuple[model.Event, int]] = []
        # A queue of futures
        # Each waiting "dequeuer" adds a future to the queue and waits on it
        # When an event becomes available, the first future in the queue is resolved, which
        # "wakes up" the corresponding dequeuer to read the event from the queue
        self._futures: typing.Deque[asyncio.Future] = collections.deque()
        # A set of service names for which there is an active processing task
        self._active: typing.Set[str] = set()
        # A map of handles to requeue callbacks
        self._handles: typing.Dict[str, asyncio.TimerHandle] = {}

    def _wakeup_next_dequeue(self):
        # Wake up the next eligible dequeuer by resolving the first future in the queue
        while self._futures:
            future = self._futures.popleft()
            if not future.done():
                future.set_result(None)
                break

    async def dequeue(self) -> typing.Tuple[model.Event, int]:
        """
        Remove and return an event from the queue.

        If the queue is empty, wait until an event is available.
        """
        while True:
            # Find the index of the first event in the queue for which there is no active task
            idx = -1
            for i, (event, _) in enumerate(self._queue):
                if event.service.name not in self._active:
                    idx = i
                    break
            # If there is such an event, extract it from the queue and return it
            if idx >= 0:
                item = self._queue[idx]
                self._queue = self._queue[0:idx] + self._queue[(idx + 1) :]
                # Register the service for the event as having an active processing task
                self._active.add(item[0].service.name)
                return item
            # If there is no such event, wait to be woken up when the situation changes
            future = asyncio.get_running_loop().create_future()
            self._futures.append(future)
            await future

    def _do_enqueue(self, event: model.Event, retries: int = 0):
        # Cancel any pending requeues for the same service
        self._cancel_requeue(event.service)
        # Append the event to the queue
        self._queue = [*self._queue, (event, retries)]
        # Wake up the next waiting dequeuer
        self._wakeup_next_dequeue()

    def enqueue(self, event: model.Event):
        """
        Add a new event to the queue.
        """
        # Discard any events for the same service from the queue
        self._queue = [
            (e, r) for e, r in self._queue if e.service.name != event.service.name
        ]
        # Add the new event to the end of the queue
        self._do_enqueue(event)

    def _do_requeue(self, event: model.Event, retries: int):
        # If there is already an event for the service on the queue, the event is discarded
        # If not, enqueue it
        if not any(e.service.name == event.service.name for e, _ in self._queue):
            self._do_enqueue(event, retries)
        else:
            self._cancel_requeue(event.service)

    def _cancel_requeue(self, service: model.Service):
        # Cancel and discard any requeue handle for the same service
        handle = self._handles.pop(service.name, None)
        if handle:
            handle.cancel()

    def requeue(self, event: model.Event, retries: int):
        """
        Requeue an event after a delay.

        The delay is calculated using an exponential backoff with the number of retries.

        If a new event for the same service is already in the queue when the delay has elapsed,
        the event is discarded.
        """
        # If there is already an existing requeue handle, cancel it
        self._cancel_requeue(event.service)
        # If there is already an event for the same service on the queue, there is nothing to do
        # If not, schedule a requeue after a delay
        #
        # NOTE(mkjpryor)
        # We use a callback rather than a task to schedule the requeue
        # This is because it allows us to cancel the requeue cleanly without trapping
        # CancelledError, allowing the processor as a whole to be cancelled reliably
        if not any(e.service.name == event.service.name for e, _ in self._queue):
            # Calculate the backoff to use
            backoff = 2**retries + random.uniform(0, 1)
            clamped_backoff = min(backoff, self.requeue_max_backoff)
            # Schedule the requeue for the future and stash the handle
            loop = asyncio.get_running_loop()
            self._handles[event.service.name] = loop.call_later(
                clamped_backoff, self._do_requeue, event, retries + 1
            )
        # Marking processing as complete may make another event eligible for processing
        self.processing_complete(event)

    def processing_complete(self, event: model.Event):
        """
        Indicates to the queue that processing for the given event is complete.
        """
        self._active.discard(event.service.name)
        # Completing processing for an event may make another event eligible for processing
        self._wakeup_next_dequeue()


class RetryRequired(Exception):
    """
    Raised to explicitly request a retry with a warning message.
    """


class Processor:
    """
    Processes service events.
    """

    def __init__(self, logger, worker_count: int, retry_max_backoff: int):
        self.logger = logger
        self.worker_count = worker_count
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

    async def metrics(self) -> typing.Iterable[metrics.Metric]:
        """
        Produce metrics for the processor.
        """
        return []

    async def process_events(self, queue: EventQueue, worker_num: int):
        """
        Process events from the given queue.
        """
        # We handle each event by calling separate updated/deleted methods
        while True:
            event, retries = await queue.dequeue()
            self.logger.info(
                "Processing %s event for %s on worker %d (attempt %d)",
                event.kind.name,
                event.service.name,
                worker_num,
                retries + 1,
            )
            try:
                # When a service has no active endpoints, we want to remove it
                if event.kind == model.EventKind.DELETED or not event.service.endpoints:
                    await self.service_removed(event.service)
                else:
                    await self.service_updated(event.service)
            except asyncio.CancelledError:
                # Propagate any cancellations with no further action
                raise
            except Exception as exc:
                if isinstance(exc, RetryRequired):
                    # If a retry is explicitly requested, just issue a warning
                    self.logger.warning(
                        "Retry required for %s event for %s - %s",
                        event.kind.name,
                        event.service.name,
                        str(exc),
                    )
                else:
                    # For all other exceptions, log the exception traceback
                    self.logger.exception(
                        "Error processing %s event for %s",
                        event.kind.name,
                        event.service.name,
                    )
                # Requeue the event for another attempt
                queue.requeue(event, retries)
            else:
                self.logger.info(
                    "Successfully processed %s event for %s",
                    event.kind.name,
                    event.service.name,
                )
                # Indicate to the queue that the processing is complete
                queue.processing_complete(event)

    async def enqueue_events(
        self, queue: EventQueue, events: typing.AsyncIterable[model.Event]
    ):
        """
        Add events from the given async iterable to the given event queue for processing.
        """
        async for event in events:
            self.logger.info(
                "Enqueuing %s event for %s", event.kind.name, event.service.name
            )
            queue.enqueue(event)

    async def run(self, store: store.Store):
        """
        Run the processor against services and events from the given store.
        """
        # The queue is used to coordinate work between the worker tasks
        queue = EventQueue(self.retry_max_backoff)
        # Begin watching the store
        initial_services, events = await store.watch()
        # Enqueue the events required to bring the observed state to the initial desired state
        known_services = await self.known_services()
        for service in initial_services:
            queue.enqueue(model.Event(model.EventKind.UPDATED, service))
        for name in known_services.difference(s.name for s in initial_services):
            queue.enqueue(model.Event(model.EventKind.DELETED, model.Service(name)))
        self.logger.info("Launching with %d worker processes", self.worker_count)
        # Set up the producer and consumer tasks
        tasks = [
            # Task to enqueue events from the store
            asyncio.create_task(self.enqueue_events(queue, events)),
            # Worker tasks to process events from the queue
            # The number of workers is the number of events that can be processed concurrently
            *[
                asyncio.create_task(self.process_events(queue, idx))
                for idx in range(self.worker_count)
            ],
        ]
        # All of the tasks should run forever, so we exit when the first one completes
        done, not_done = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in not_done:
            await util.task_cancel_and_wait(task)
        for task in done:
            task.result()

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
