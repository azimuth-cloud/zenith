import datetime

from kube_custom_resource import CustomResource, schema
from pydantic import Field


class LeaseSpec(schema.BaseModel):
    """
    Model for the spec of a lease resource.
    """

    renewed_at: datetime.datetime = Field(
        ..., description="Time at which the lease was renewed."
    )
    ttl: schema.conint(gt=0) = Field(
        ..., description="Number of seconds after which the lease expires."
    )
    reap_after: schema.conint(gt=0) = Field(
        ..., description="Number of seconds after which the lease should be reaped."
    )


class Lease(
    CustomResource,
    subresources={"status": {}},
    printer_columns=[
        {
            "name": "Renewed",
            "type": "date",
            "jsonPath": ".spec.renewedAt",
        },
        {
            "name": "TTL",
            "type": "integer",
            "jsonPath": ".spec.ttl",
        },
        {
            "name": "Reap After",
            "type": "integer",
            "jsonPath": ".spec.reapAfter",
        },
    ],
):
    """
    Custom resource for a lease for a Zenith tunnel.
    """

    spec: LeaseSpec = Field(..., description="The spec for the lease resource.")
