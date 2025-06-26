import datetime  # noqa: F401

from pydantic import Field

from kube_custom_resource import CustomResource, schema


class EndpointStatus(schema.Enum):
    """
    Enumeration of possible endpoint statuses.
    """

    PASSING = "passing"
    WARNING = "warning"
    CRITICAL = "critical"


class Endpoint(schema.BaseModel):
    """
    Model for an endpoint.
    """

    address: schema.constr(min_length=1) = Field(
        ..., description="The address for the endpoint."
    )
    port: schema.conint(gt=0) = Field(..., description="The port for the endpoint.")
    status: EndpointStatus = Field(..., description="The status of the endpoint.")
    config: schema.Dict[str, schema.Any] = Field(
        default_factory=dict, description="The config for the endpoint."
    )


class EndpointsSpec(schema.BaseModel):
    """
    Model for the spec of an endpoints resource.
    """

    endpoints: schema.Dict[str, Endpoint] = Field(
        default_factory=dict, description="The endpoints, indexed by ID."
    )


class Endpoints(
    CustomResource,
    plural_name="endpoints",
    subresources={"status": {}},
    printer_columns=[],
):
    """
    Custom resource for the endpoints of a Zenith service.
    """

    spec: EndpointsSpec = Field(
        default_factory=EndpointsSpec,
        description="The spec for the endpoints resource.",
    )
