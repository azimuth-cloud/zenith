import asyncio
import contextlib

from . import config
from .processor import load as load_processor
from .store import load as load_store


async def run(config_obj: config.SyncConfig):
    """
    Synchronises Consul services with Kubernetes.
    """
    async with contextlib.AsyncExitStack() as stack:
        processor = await stack.enter_async_context(load_processor(config_obj))
        store = await stack.enter_async_context(load_store(config_obj))
        # Both the processor and store should run forever if there are no problems
        # We can't use gather because we want the entire command to exit if one
        # of the coroutines exits, even if that exit is clean
        done, not_done = await asyncio.wait(
            [processor.run(store), store.run()],
            return_when = asyncio.FIRST_COMPLETED
        )
        # However any exceptions are not raised until we try to fetch the results
        for task in not_done:
            task.cancel()
        for task in done:
            task.result()
