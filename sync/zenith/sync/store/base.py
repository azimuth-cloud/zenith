import asyncio
import typing

from .. import config, metrics, model


class Store:
    """
    Produces events when the underlying representation of a service changes.
    """
    async def metrics(self) -> typing.Iterable[metrics.Metric]:
        """
        Produce metrics for the processor.
        """
        return []

    async def watch(self) -> typing.Tuple[
        typing.Iterable[model.Service],
        typing.AsyncIterable[model.Event]
    ]:
        """
        Connect to the store and return a tuple of (initial services, async iterable of events).
        """
        raise NotImplementedError

    async def run(self):
        """
        Run any long-running tasks associated with the store.
        """
        # By default, this loops forever
        while True:
            await asyncio.sleep(86400)

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
    def from_config(cls, config_obj: config.SyncConfig) -> "Store":
        """
        Initialises an instance of the store from a config object.
        """
        raise NotImplementedError
