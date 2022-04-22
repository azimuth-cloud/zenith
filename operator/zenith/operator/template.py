import jinja2
import json
import yaml

from pydantic.json import pydantic_encoder

from .config import settings
from . import models, utils


def toyaml(obj):
    """
    Filter for converting an object to YAML that is able to handle Pydantic models.
    """
    # In order to benefit from the Pydantic encoder we need to go via JSON
    obj_json = json.dumps(obj, default = pydantic_encoder)
    return yaml.safe_dump(json.loads(obj_json))


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
            toyaml = toyaml
        )

    def loads(self, template, **params):
        """
        Render the specified template with the given params and return the result as a string.
        """
        return self.env.get_template(template).render(**params)

    def load(self, template, **params):
        """
        Render the specified template with the given params, load the result as a YAML document
        and return the resulting object.
        """
        return yaml.safe_load(self.loads(template, **params))


default_loader = Loader(settings = settings, models = models)
