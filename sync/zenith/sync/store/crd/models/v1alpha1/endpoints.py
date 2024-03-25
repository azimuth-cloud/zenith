from pydantic import Field

from kube_custom_resource import CustomResource, schema


class EndpointsSpec(schema.BaseModel):
    """
    Model for the spec of an endpoints resource.
    """


class Endpoints(
    CustomResource,
    plural_name = "endpoints",
    subresources = {"status": {}},
    printer_columns = []
):
    """
    Custom resource for the endpoints of a Zenith service.
    """
    spec: EndpointsSpec = Field(
        default_factory = EndpointsSpec,
        description = "The spec for the endpoints resource."
    )
