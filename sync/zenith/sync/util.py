import asyncio
import functools


def _resolve_future(future, task):
    if not future.done():
        try:
            # Try to resolve the future with the result of the task
            future.set_result(task.result())
        except BaseException as exc:
            # If the task raises an exception, resolve with that
            future.set_exception(exc)


async def task_cancel_and_wait(task):
    """
    Cancel the task and wait for it to exit.
    """
    # We cannot wait on the task directly as we want this function to be cancellable
    # e.g. the task might be shielded from cancellation
    # Instead, we make a future that completes when the task completes and wait on that
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    callback = functools.partial(_resolve_future, future)
    task.add_done_callback(callback)

    try:
        # Cancel the task, but wait on our proxy future
        task.cancel()
        await future
    except asyncio.CancelledError:
        # Suppress the cancelled exception as we no longer need it
        pass
    finally:
        task.remove_done_callback(callback)
