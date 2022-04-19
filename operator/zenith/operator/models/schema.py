import enum
import typing

from pydantic import Extra

from configomatic import Section


class Enum(enum.Enum):
    """
    Enum that does not include a title in the JSON-Schema.
    """
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

    @classmethod
    def schema(cls, *args, **kwargs):
        schema = super().schema(*args, **kwargs)
        # If the schema has definitions defined, resolve $refs and remove them
        if "definitions" in schema:
            resolve_refs(schema, schema.pop("definitions"))
        return schema
