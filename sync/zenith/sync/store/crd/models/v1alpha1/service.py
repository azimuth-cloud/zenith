from pydantic import Field

from kube_custom_resource import CustomResource, schema


class ServiceSpec(schema.BaseModel):
    """
    Model for the spec of a service resource.
    """


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
