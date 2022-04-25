import enum
import typing

from pydantic import Extra, ValidationError

from configomatic import Section


class Enum(enum.Enum):
    """
    Enum that does not include a title in the JSON-Schema.
    """
    def __str__(self):
        return str(self.value)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.pop("title", None)


class Dict(typing.Dict):
    """
    Dict whose JSON-Schema includes the custom attribute to prevent Kubernetes
    pruning unknown properties.
    """
    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema["x-kubernetes-preserve-unknown-fields"] = True


class IntOrString(str):
    """
    Type for a value that can be specified as an integer or a string.

    The value will resolve to a string and the generated schema will include the
    Kubernetes custom schema attribute 'x-kubernetes-int-or-string'.
    """
    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.pop("type", None)
        field_schema.update({
            "x-kubernetes-int-or-string": True,
            "anyOf": [
                { "type": "integer" },
                { "type": "string" },
            ],
        })

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, (str, int)):
            raise TypeError("int or string required")
        return str(v)


def resolve_refs(schema, definitions):
    """
    Recursively resolve $refs in the given schema using the definitions.
    """
    if isinstance(schema, dict):
        if "allOf" in schema and len(schema["allOf"]) == 1:
            # Where the schema has an allOf with a single item, just put the
            # fields from the item onto the schema
            items = schema.pop("allOf")[0]
            resolve_refs(items, definitions)
            schema.update(items)
        elif "$ref" in schema:
            ref = schema.pop("$ref").removeprefix("#/definitions/")
            referenced = definitions[ref]
            resolve_refs(referenced, definitions)
            schema.update(definitions[ref])
        else:
            for value in schema.values():
                resolve_refs(value, definitions)
    elif isinstance(schema, list):
        for item in schema:
            resolve_refs(item, definitions)


class BaseModel(Section):
    """
    Base model for use within CRD definitions.
    """
    class Config:
        # Validate any mutations to the model
        allow_mutation = True
        validate_assignment = True

        @staticmethod
        def schema_extra(schema, model):
            """
            Post-process the generated schema to make it compatible with a Kubernetes CRD.
            """
            # Remove the titles
            schema.pop("title", None)
            for prop in schema.get("properties", {}).values():
                prop.pop("title", None)
            # When extra fields are allowed, stop Kubernetes pruning them
            if model.__config__.extra == Extra.allow:
                schema["x-kubernetes-preserve-unknown-fields"] = True
            # If an instance can be produced with no arguments without an error, use it
            # as the default value
            try:
                instance = model()
            except ValidationError:
                pass
            else:
                schema.setdefault("default", instance.dict(exclude_none = True))

    def dict(self, **kwargs):
        # Unless otherwise specified, we want by_alias = True
        kwargs.setdefault("by_alias", True)
        return super().dict(**kwargs)

    def json(self, **kwargs):
        # Unless otherwise specified, we want by_alias = True
        kwargs.setdefault("by_alias", True)
        return super().json(**kwargs)

    @classmethod
    def schema(cls, *args, **kwargs):
        schema = super().schema(*args, **kwargs)
        # If the schema has definitions defined, resolve $refs and remove them
        if "definitions" in schema:
            resolve_refs(schema, schema.pop("definitions"))
        return schema
