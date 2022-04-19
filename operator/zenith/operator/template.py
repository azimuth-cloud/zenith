import jinja2
import yaml

from .config import settings
from . import models, utils


class Loader:
    """
    Class for returning objects created by rendering YAML templates from this package.
    """
    def __init__(self, **globals):
        # Create the package loader for the parent module of this one
        loader = jinja2.PackageLoader(self.__module__.rsplit(".", maxsplit = 1)[0])
        self.env = jinja2.Environment(loader = loader, autoescape = False)
        self.env.globals.update(globals)
        self.env.filters.update(
            mergeconcat = utils.mergeconcat,
            fromyaml = yaml.safe_load,
            toyaml = yaml.safe_dump
        )

    def loads(self, template, **params):
        """
        Render the specified template with the given params and return the result as a string.
        """
        return self.env.get_template(template).render(**params)

    def load(self, template, **params):
        """
        Render the specified template with the given params, load the result as YAML and
        return the resulting object.
        """
        return yaml.safe_load(self.loads(template, **params))


default_loader = Loader(settings = settings, models = models)
