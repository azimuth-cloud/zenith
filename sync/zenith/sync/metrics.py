import asyncio
import functools
import typing

from aiohttp import web

if typing.TYPE_CHECKING:
    from .processor import Processor
    from .store import Store


class Metric:
    """
    Base class for metrics.
    """
    # The prefix for the metric
    prefix = None
    # The suffix for the metric
    suffix = None
    # The type of the metric - info or guage
    type = "info"
    # The description of the metric
    description = None

    def __init__(self):
        self._objs = []

    def add_obj(self, obj):
        self._objs.append(obj)

    @property
    def name(self):
        return f"{self.prefix}_{self.suffix}"

    def labels(self, obj):
        """
        The labels for the given object.
        """
        return {}

    def value(self, obj):
        """
        The value for the given object.
        """
        return 1

    def samples(self):
        """
        Returns the samples for the metric, i.e. a list of (labels, value) tuples.
        """
        for obj in self._objs:
            yield self.labels(obj), self.value(obj)


def escape(content):
    """
    Escape the given content for use in metric output.
    """
    return str(content).replace("\\", r"\\").replace("\n", r"\n").replace('"', r"\"")


def format_value(value):
    """
    Formats a value for output, e.g. using Go formatting.
    """
    formatted = repr(value)
    dot = formatted.find('.')
    if value > 0 and dot > 6:
        mantissa = f"{formatted[0]}.{formatted[1:dot]}{formatted[dot + 1:]}".rstrip("0.")
        return f"{mantissa}e+0{dot - 1}"
    else:
        return formatted


def render_openmetrics(*metrics: Metric) -> typing.Tuple[str, bytes]:
    """
    Renders the metrics using OpenMetrics text format.
    """
    output = []
    for metric in metrics:
        if metric.description:
            output.append(f"# HELP {metric.name} {escape(metric.description)}\n")
        output.append(f"# TYPE {metric.name} {metric.type}\n")

        for labels, value in metric.samples():
            if labels:
                labelstr = "{{{0}}}".format(
                    ",".join([f'{k}="{escape(v)}"' for k, v in sorted(labels.items())])
                )
            else:
                labelstr = ""
            output.append(f"{metric.name}{labelstr} {format_value(value)}\n")
    output.append("# EOF\n")

    return (
        "application/openmetrics-text; version=1.0.0; charset=utf-8",
        "".join(output).encode("utf-8"),
    )


async def metrics_handler(store: 'Store', processor: 'Processor', request):
    """
    Produce metrics for the store and processor.
    """
    store_metrics, processor_metrics = await asyncio.gather(store.metrics(), processor.metrics())
    content_type, content = render_openmetrics(*store_metrics, *processor_metrics)
    return web.Response(headers = {"Content-Type": content_type}, body = content)


async def metrics_server(store: 'Store', processor: 'Processor'):
    """
    Launch a lightweight HTTP server to serve the metrics endpoint.
    """
    app = web.Application()
    app.add_routes([web.get("/metrics", functools.partial(metrics_handler, store, processor))])

    runner = web.AppRunner(app, handle_signals = False)
    await runner.setup()

    site = web.TCPSite(runner, "0.0.0.0", "8080", shutdown_timeout = 1.0)
    await site.start()

    # Sleep until we need to clean up
    try:
        await asyncio.Event().wait()
    finally:
        await asyncio.shield(runner.cleanup())
