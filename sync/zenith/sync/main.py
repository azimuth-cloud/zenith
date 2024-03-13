import asyncio

from . import config, reconcilers, watchers


async def run(config_obj: config.SyncConfig):
    """
    Synchronises Consul services with Kubernetes.
    """
    reconciler = reconcilers.load(config_obj)
    watcher = watchers.load(config_obj)
    # Both the reconciler and watcher should run forever if there are no problems
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
