from pydantic import Field

from kube_custom_resource import CustomResource, schema


class ServiceSpec(schema.BaseModel):
    """
    Model for the spec of a service resource.
    """
    public_key_fingerprint: schema.Optional[schema.constr(min_length = 1)] = Field(
        None,
        description = "The fingerprint of the public key for the service.",
        validate_default = True
    )


class Service(
    CustomResource,
    subresources = {"status": {}},
    printer_columns = []
):
    """
    Custom resource for a Zenith service.
    """
    spec: ServiceSpec = Field(
        default_factory = ServiceSpec,
        description = "The spec for the service resource."
    )
