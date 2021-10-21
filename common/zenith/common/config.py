import logging

from pydantic import BaseModel, validator
import yaml

from configomatic import ConfigurableObject


def snake_to_pascal(name):
    """
    Converts a snake case name to pascalCase.
    """
    first, *rest = name.split("_")
    return "".join([first] + [part.capitalize() for part in rest])


class LessThanLevelFilter(logging.Filter):
    def __init__(self, level):
        if isinstance(level, int):
            self.level = level
        else:
            self.level = getattr(logging, level.upper())

    def filter(self, record):
        return record.levelno < self.level


class Section(BaseModel):
    """
    Base class for a configuration section.
    """
    class Config:
        alias_generator = snake_to_pascal
        allow_population_by_field_name = True


class Configuration(ConfigurableObject):
    """
    Base model for a configuration.
    """
    class Config:
        load_file = yaml.safe_load
        alias_generator = snake_to_pascal
        allow_population_by_field_name = True

    #: The logging configuration
    # See https://docs.python.org/3/library/logging.config.html#logging-config-dictschema
    logging: dict = None

    @validator("logging", always = True)
    def validate_logging(cls, v):
        return v or {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "[%(levelname)s] %(message)s",
                },
            },
            "filters": {
                # This filter allows us to send >= WARNING to stderr and < WARNING to stdout
                "less_than_warning": {
                    "()": f"{__name__}.LessThanLevelFilter",
                    "level": "WARNING",
                },
            },
            "handlers": {
                "stdout": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "formatter": "default",
                    "filters": ["less_than_warning"],
                },
                "stderr": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stderr",
                    "formatter": "default",
                    "level": "WARNING",
                },
            },
            "loggers": {
                "": {
                    "handlers": ["stdout", "stderr"],
                    "level": "INFO",
                    "propagate": True
                },
            },
        }
