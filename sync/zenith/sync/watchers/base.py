import asyncio
import typing as t

from .. import config, model


class ServiceWatcher:
    """
    Allows clients to watch changes to the set of Zenith services.
    """
    async def subscribe(self) -> t.Tuple[
        t.Iterable[model.Service],
        asyncio.Queue[model.Event],
        t.Callable[[], None]
    ]:
        """
        Subscribe to changes to the set of services.

        Returns a tuple of (current services, queue of events, unsubscribe function).
        """
        raise NotImplementedError

    async def run(self):
        """
        Starts the watcher and runs until cancelled.
        """
        raise NotImplementedError

    @classmethod
    def from_config(cls, config_obj: config.SyncConfig) -> "ServiceWatcher":
        """
        Initialises an instance of the watcher from a config object.
        """
        raise NotImplementedError
