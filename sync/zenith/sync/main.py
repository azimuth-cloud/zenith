import asyncio

from .consul import ServiceWatcher
from .kubernetes import ServiceReconciler


async def run(config):
    """
    Synchronises Consul services with Kubernetes.
    """
    watcher = ServiceWatcher(config.consul)
    reconciler = ServiceReconciler(config.kubernetes)
    # Both run coroutines should run forever if there are no problems
    # We can't use gather because we want the entire command to exit if one
    # of the coroutines exits, even if that exit is clean
    done, not_done = await asyncio.wait(
        [watcher.run(), reconciler.run(watcher)],
        return_when = asyncio.FIRST_COMPLETED
    )
    # However any exceptions are not raised until we try to fetch the results
    for task in not_done:
        task.cancel()
    for task in done:
        task.result()
